package core

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Krive/ServiceNow-SDK/pkg/utils/ratelimit"
	"github.com/Krive/ServiceNow-SDK/pkg/utils/retry"
	"github.com/go-resty/resty/v2"
)

type Client struct {
	InstanceURL string // Root instance URL for non-/api/now endpoints
	BaseURL     string
	Client      *resty.Client
	Auth        AuthProvider
	rateLimiter *ratelimit.ServiceNowLimiter
	retryConfig retry.Config
	timeout     time.Duration
}

func NewClientBasicAuth(instanceURL, username, password string) (*Client, error) {
	return newClient(instanceURL, NewBasicAuth(username, password))
}

func NewClientOAuth(instanceURL, clientID, clientSecret string) (*Client, error) {
	return newClient(instanceURL, NewOAuthClientCredentials(instanceURL, clientID, clientSecret))
}

func NewClientOAuthWithStorage(instanceURL, clientID, clientSecret string, storage TokenStorage) (*Client, error) {
	if storage == nil {
		return NewClientOAuth(instanceURL, clientID, clientSecret)
	}
	return newClient(instanceURL, NewOAuthClientCredentialsWithStorage(instanceURL, clientID, clientSecret, storage))
}

func NewClientOAuthRefresh(instanceURL, clientID, clientSecret, refreshToken string) (*Client, error) {
	return newClient(instanceURL, NewOAuthAuthorizationCode(instanceURL, clientID, clientSecret, refreshToken))
}

func NewClientOAuthRefreshWithStorage(instanceURL, clientID, clientSecret, refreshToken string, storage TokenStorage) (*Client, error) {
	if storage == nil {
		return NewClientOAuthRefresh(instanceURL, clientID, clientSecret, refreshToken)
	}
	return newClient(instanceURL, NewOAuthAuthorizationCodeWithStorage(instanceURL, clientID, clientSecret, refreshToken, storage))
}

func NewClientAPIKey(instanceURL, apiKey string) (*Client, error) {
	return newClient(instanceURL, NewAPIKeyAuth(apiKey))
}

func newClient(instanceURL string, auth AuthProvider) (*Client, error) {
	c := resty.New()
	c.SetBaseURL(instanceURL + "/api/now")
	c.SetHeader("Accept", "application/json")
	c.SetHeader("Content-Type", "application/json")
	c.SetTimeout(30 * time.Second) // Default timeout

	if err := auth.Apply(c); err != nil {
		return nil, fmt.Errorf("failed to apply auth: %w", err)
	}

	// Initialize rate limiter with default ServiceNow configuration
	rateLimiter := ratelimit.NewServiceNowLimiter(ratelimit.DefaultServiceNowConfig())

	// Initialize retry configuration optimized for ServiceNow
	retryConfig := retry.ServiceNowRetryConfig()

	return &Client{
		InstanceURL: instanceURL,
		BaseURL:     instanceURL + "/api/now",
		Client:      c,
		Auth:        auth,
		rateLimiter: rateLimiter,
		retryConfig: retryConfig,
		timeout:     30 * time.Second,
	}, nil
}

const (
	FormatJSON = "json"
	FormatXML  = "xml"
)

// HandleResponse processes API responses with format support
func (c *Client) HandleResponse(resp *resty.Response, err error, target interface{}, format string) error {
	if err != nil {
		return classifyRequestError(err)
	}
	if resp == nil {
		return fmt.Errorf("no response received")
	}
	if !resp.IsSuccess() {
		// Attempt to parse error response (assume JSON for errors)
		var snErr struct {
			Error struct {
				Message string `json:"message"`
				Detail  string `json:"detail"`
			} `json:"error"`
		}
		if jsonErr := json.Unmarshal(resp.Body(), &snErr); jsonErr == nil && snErr.Error.Message != "" {
			return NewServiceNowErrorWithDetail(resp.StatusCode(), snErr.Error.Message, snErr.Error.Detail)
		}
		return NewServiceNowError(resp.StatusCode(), string(resp.Body()))
	}
	if target != nil {
		body := resp.Body()
		switch format {
		case FormatXML:
			return xml.Unmarshal(body, target)
		case FormatJSON:
			fallthrough
		default:
			return json.Unmarshal(body, target)
		}
	}
	return nil
}

// RawRequest allows low-level API calls with auth handling (default JSON)
func (c *Client) RawRequest(method, path string, body interface{}, params map[string]string, result interface{}) error {
	return c.RawRequestWithContext(context.Background(), method, path, body, params, result)
}

// RawRequestWithContext allows low-level API calls with context support
func (c *Client) RawRequestWithContext(ctx context.Context, method, path string, body interface{}, params map[string]string, result interface{}) error {
	// Determine endpoint type for rate limiting
	endpointType := ratelimit.DetectEndpointType(path)

	// Apply rate limiting
	if err := c.rateLimiter.Wait(ctx, endpointType); err != nil {
		return fmt.Errorf("rate limit wait failed: %w", err)
	}

	// Execute with retry logic
	return retry.Do(ctx, c.retryConfig, func() error {
		return c.executeRequest(ctx, method, path, body, params, result, FormatJSON)
	})
}

// executeRequest performs the actual HTTP request
func (c *Client) executeRequest(ctx context.Context, method, path string, body interface{}, params map[string]string, result interface{}, format string) error {
	if err := c.Auth.Apply(c.Client); err != nil {
		return fmt.Errorf("failed to apply auth: %w", err)
	}

	req := c.Client.R().SetContext(ctx)
	if body != nil {
		req.SetBody(body)
	}
	for k, v := range params {
		req.SetQueryParam(k, v)
	}

	resp, err := req.Execute(method, path)
	return c.HandleResponse(resp, err, result, format)
}

// RawRootRequest allows low-level calls to root instance URL (e.g., for .do endpoints) with format
func (c *Client) RawRootRequest(method, path string, body interface{}, params map[string]string, result interface{}, format string) error {
	return c.RawRootRequestWithContext(context.Background(), method, path, body, params, result, format)
}

// RawRootRequestWithContext allows low-level calls to root instance URL with context support
func (c *Client) RawRootRequestWithContext(ctx context.Context, method, path string, body interface{}, params map[string]string, result interface{}, format string) error {
	// Determine endpoint type for rate limiting
	endpointType := ratelimit.DetectEndpointType(path)

	// Apply rate limiting
	if err := c.rateLimiter.Wait(ctx, endpointType); err != nil {
		return fmt.Errorf("rate limit wait failed: %w", err)
	}

	// Execute with retry logic
	return retry.Do(ctx, c.retryConfig, func() error {
		return c.executeRootRequest(ctx, method, path, body, params, result, format)
	})
}

// executeRootRequest performs the actual HTTP request to root URL
func (c *Client) executeRootRequest(ctx context.Context, method, path string, body interface{}, params map[string]string, result interface{}, format string) error {
	if err := c.Auth.Apply(c.Client); err != nil {
		return fmt.Errorf("failed to apply auth: %w", err)
	}

	req := c.Client.R().SetContext(ctx)
	if format == FormatXML {
		req.SetHeader("Accept", "application/xml")
	}
	if body != nil {
		req.SetBody(body)
	}
	for k, v := range params {
		req.SetQueryParam(k, v)
	}
	requestURL := path
	if !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") {
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		requestURL = c.InstanceURL + path
	}
	resp, err := req.Execute(method, requestURL)
	return c.HandleResponse(resp, err, result, format)
}

// UploadFileWithContext uploads a file via multipart form data with auth, rate limiting and retry.
func (c *Client) UploadFileWithContext(
	ctx context.Context,
	path string,
	fileField string,
	filePath string,
	formData map[string]string,
	result interface{},
) error {
	endpointType := ratelimit.DetectEndpointType(path)
	if err := c.rateLimiter.Wait(ctx, endpointType); err != nil {
		return fmt.Errorf("rate limit wait failed: %w", err)
	}

	return retry.Do(ctx, c.retryConfig, func() error {
		if err := c.Auth.Apply(c.Client); err != nil {
			return fmt.Errorf("failed to apply auth: %w", err)
		}

		req := c.Client.R().SetContext(ctx).SetMultipartFormData(formData).SetFile(fileField, filePath)
		resp, err := req.Post(path)
		return c.HandleResponse(resp, err, result, FormatJSON)
	})
}

// DownloadFileWithContext downloads a file to disk with auth, rate limiting and retry.
func (c *Client) DownloadFileWithContext(ctx context.Context, path string, params map[string]string, outputPath string) error {
	endpointType := ratelimit.DetectEndpointType(path)
	if err := c.rateLimiter.Wait(ctx, endpointType); err != nil {
		return fmt.Errorf("rate limit wait failed: %w", err)
	}

	return retry.Do(ctx, c.retryConfig, func() error {
		if err := c.Auth.Apply(c.Client); err != nil {
			return fmt.Errorf("failed to apply auth: %w", err)
		}

		req := c.Client.R().SetContext(ctx).SetOutput(outputPath)
		for k, v := range params {
			req.SetQueryParam(k, v)
		}

		resp, err := req.Get(path)
		if err != nil {
			return classifyRequestError(err)
		}
		if !resp.IsSuccess() {
			return c.HandleResponse(resp, nil, nil, FormatJSON)
		}
		return nil
	})
}

func classifyRequestError(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, context.Canceled) {
		return err
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return NewTimeoutError(err.Error())
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return NewTimeoutError(netErr.Error())
		}
		return &ServiceNowError{
			Type:       ErrorTypeNetwork,
			Message:    netErr.Error(),
			Code:       "NETWORK_ERROR",
			StatusCode: 0,
			Retryable:  true,
		}
	}

	return err
}

// SetTimeout sets the request timeout for the client
func (c *Client) SetTimeout(timeout time.Duration) {
	c.timeout = timeout
	c.Client.SetTimeout(timeout)
}

// GetTimeout returns the current request timeout
func (c *Client) GetTimeout() time.Duration {
	return c.timeout
}

// SetRetryConfig updates the retry configuration
func (c *Client) SetRetryConfig(config retry.Config) {
	c.retryConfig = config
}

// GetRetryConfig returns the current retry configuration
func (c *Client) GetRetryConfig() retry.Config {
	return c.retryConfig
}

// SetRateLimitConfig updates the rate limiting configuration
func (c *Client) SetRateLimitConfig(config ratelimit.ServiceNowLimiterConfig) {
	c.rateLimiter.UpdateConfig(config)
}

// GetRateLimiter returns the rate limiter for advanced usage
func (c *Client) GetRateLimiter() *ratelimit.ServiceNowLimiter {
	return c.rateLimiter
}
