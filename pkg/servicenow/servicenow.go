package servicenow

import (
	"fmt"
	"time"

	"github.com/Krive/ServiceNow-SDK/pkg/servicenow/aggregate"
	"github.com/Krive/ServiceNow-SDK/pkg/servicenow/attachment"
	"github.com/Krive/ServiceNow-SDK/pkg/servicenow/batch"
	"github.com/Krive/ServiceNow-SDK/pkg/servicenow/catalog"
	"github.com/Krive/ServiceNow-SDK/pkg/servicenow/cmdb"
	"github.com/Krive/ServiceNow-SDK/pkg/servicenow/core"
	"github.com/Krive/ServiceNow-SDK/pkg/servicenow/identity"
	"github.com/Krive/ServiceNow-SDK/pkg/servicenow/importset"
	"github.com/Krive/ServiceNow-SDK/pkg/servicenow/table"
	"github.com/Krive/ServiceNow-SDK/pkg/utils/ratelimit"
	"github.com/Krive/ServiceNow-SDK/pkg/utils/retry"
)

// Client represents the main ServiceNow SDK client
type Client struct {
	core *core.Client
}

// Config holds configuration options for the ServiceNow client
type Config struct {
	InstanceURL string
	// AllowInsecureHTTP permits plain HTTP instance URLs for local/test environments.
	// Keep false in production.
	AllowInsecureHTTP bool
	// AllowCrossHostRootRequests permits RawRootRequest absolute URLs to hosts
	// other than InstanceURL. Keep false unless explicitly required.
	AllowCrossHostRootRequests bool
	// Authentication options (only one should be set)
	Username     string            // For basic auth
	Password     string            // For basic auth
	ClientID     string            // For OAuth
	ClientSecret string            // For OAuth
	RefreshToken string            // For OAuth authorization code flow
	APIKey       string            // For API key auth
	TokenStorage core.TokenStorage // Optional OAuth token storage backend

	// Performance and reliability settings
	Timeout         time.Duration                      // Request timeout
	RetryConfig     *retry.Config                      // Retry configuration
	RateLimitConfig *ratelimit.ServiceNowLimiterConfig // Rate limiting configuration
}

// NewClient creates a new ServiceNow SDK client with the provided configuration
func NewClient(config Config) (*Client, error) {
	if config.InstanceURL == "" {
		return nil, fmt.Errorf("instance URL is required")
	}

	var coreClient *core.Client
	var err error
	clientOptions := core.ClientOptions{
		AllowInsecureHTTP:          config.AllowInsecureHTTP,
		AllowCrossHostRootRequests: config.AllowCrossHostRootRequests,
	}

	// Determine auth method based on provided credentials
	if config.Username != "" && config.Password != "" {
		coreClient, err = core.NewClientBasicAuthWithOptions(config.InstanceURL, config.Username, config.Password, clientOptions)
	} else if config.APIKey != "" {
		coreClient, err = core.NewClientAPIKeyWithOptions(config.InstanceURL, config.APIKey, clientOptions)
	} else if config.ClientID != "" && config.ClientSecret != "" && config.RefreshToken != "" {
		coreClient, err = core.NewClientOAuthRefreshWithStorageAndOptions(
			config.InstanceURL,
			config.ClientID,
			config.ClientSecret,
			config.RefreshToken,
			config.TokenStorage,
			clientOptions,
		)
	} else if config.ClientID != "" && config.ClientSecret != "" {
		coreClient, err = core.NewClientOAuthWithStorageAndOptions(
			config.InstanceURL,
			config.ClientID,
			config.ClientSecret,
			config.TokenStorage,
			clientOptions,
		)
	} else {
		return nil, fmt.Errorf("authentication credentials must be provided: basic auth (username/password), API key, or OAuth (client_id/client_secret)")
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create core client: %w", err)
	}

	// Apply optional configuration settings
	if config.Timeout > 0 {
		coreClient.SetTimeout(config.Timeout)
	}

	if config.RetryConfig != nil {
		coreClient.SetRetryConfig(*config.RetryConfig)
	}

	if config.RateLimitConfig != nil {
		coreClient.SetRateLimitConfig(*config.RateLimitConfig)
	}

	return &Client{
		core: coreClient,
	}, nil
}

// NewClientBasicAuth creates a new ServiceNow client with basic authentication
func NewClientBasicAuth(instanceURL, username, password string) (*Client, error) {
	return NewClient(Config{
		InstanceURL: instanceURL,
		Username:    username,
		Password:    password,
	})
}

// NewClientOAuth creates a new ServiceNow client with OAuth authentication
func NewClientOAuth(instanceURL, clientID, clientSecret string) (*Client, error) {
	return NewClient(Config{
		InstanceURL:  instanceURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})
}

// NewClientOAuthRefresh creates a new ServiceNow client with OAuth refresh token
func NewClientOAuthRefresh(instanceURL, clientID, clientSecret, refreshToken string) (*Client, error) {
	return NewClient(Config{
		InstanceURL:  instanceURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RefreshToken: refreshToken,
	})
}

// NewClientAPIKey creates a new ServiceNow client with API key authentication
func NewClientAPIKey(instanceURL, apiKey string) (*Client, error) {
	return NewClient(Config{
		InstanceURL: instanceURL,
		APIKey:      apiKey,
	})
}

// Table returns a table client for the specified table name
func (c *Client) Table(tableName string) *table.TableClient {
	return table.NewTableClient(c.core, tableName)
}

// Attachment returns an attachment client
func (c *Client) Attachment() *attachment.AttachmentClient {
	return attachment.NewAttachmentClient(c.core)
}

// ImportSet returns an import set client
func (c *Client) ImportSet() *importset.ImportSetClient {
	return importset.NewImportSetClient(c.core)
}

// Aggregate returns an aggregate client for the specified table name
func (c *Client) Aggregate(tableName string) *aggregate.AggregateClient {
	return aggregate.NewAggregateClient(c.core, tableName)
}

// Batch returns a batch client for performing multiple operations in a single request
func (c *Client) Batch() *batch.BatchClient {
	return batch.NewBatchClient(c.core)
}

// Catalog returns a service catalog client for browsing catalogs and ordering items
func (c *Client) Catalog() *catalog.CatalogClient {
	return catalog.NewCatalogClient(c.core)
}

// CMDB returns a CMDB client for managing Configuration Items and relationships
func (c *Client) CMDB() *cmdb.CMDBClient {
	return cmdb.NewCMDBClient(c.core)
}

// Identity returns an Identity and Access Management client for managing users, roles, and groups
func (c *Client) Identity() *identity.IdentityClient {
	return identity.NewIdentityClient(c.core)
}

// Core returns the underlying core client for advanced usage
// This allows access to raw HTTP client functionality when needed
func (c *Client) Core() *core.Client {
	return c.core
}

// Advanced configuration methods

// SetTimeout updates the request timeout
func (c *Client) SetTimeout(timeout time.Duration) {
	c.core.SetTimeout(timeout)
}

// SetRetryConfig updates the retry configuration
func (c *Client) SetRetryConfig(config retry.Config) {
	c.core.SetRetryConfig(config)
}

// SetRateLimitConfig updates the rate limiting configuration
func (c *Client) SetRateLimitConfig(config ratelimit.ServiceNowLimiterConfig) {
	c.core.SetRateLimitConfig(config)
}

// GetTimeout returns the current request timeout
func (c *Client) GetTimeout() time.Duration {
	return c.core.GetTimeout()
}

// GetRetryConfig returns the current retry configuration
func (c *Client) GetRetryConfig() retry.Config {
	return c.core.GetRetryConfig()
}

// Convenience methods for common configurations

// WithConservativeRateLimit applies conservative rate limiting (safer for production)
func (c *Client) WithConservativeRateLimit() *Client {
	config := ratelimit.ServiceNowLimiterConfig{
		TableRequestsPerSecond:      2.0,
		AttachmentRequestsPerSecond: 1.0,
		ImportRequestsPerSecond:     0.5,
		DefaultRequestsPerSecond:    1.5,
		TableBurst:                  5,
		AttachmentBurst:             2,
		ImportBurst:                 1,
		DefaultBurst:                3,
	}
	c.SetRateLimitConfig(config)
	return c
}

// WithAggressiveRateLimit applies more aggressive rate limiting (higher throughput)
func (c *Client) WithAggressiveRateLimit() *Client {
	config := ratelimit.ServiceNowLimiterConfig{
		TableRequestsPerSecond:      10.0,
		AttachmentRequestsPerSecond: 5.0,
		ImportRequestsPerSecond:     2.0,
		DefaultRequestsPerSecond:    7.0,
		TableBurst:                  20,
		AttachmentBurst:             10,
		ImportBurst:                 5,
		DefaultBurst:                15,
	}
	c.SetRateLimitConfig(config)
	return c
}

// WithMinimalRetry applies minimal retry configuration
func (c *Client) WithMinimalRetry() *Client {
	config := retry.Config{
		MaxAttempts: 2,
		BaseDelay:   200 * time.Millisecond,
		MaxDelay:    5 * time.Second,
		Multiplier:  1.5,
		Jitter:      true,
		RetryOn: []core.ErrorType{
			core.ErrorTypeRateLimit,
		},
	}
	c.SetRetryConfig(config)
	return c
}

// WithAggressiveRetry applies aggressive retry configuration
func (c *Client) WithAggressiveRetry() *Client {
	config := retry.Config{
		MaxAttempts: 7,
		BaseDelay:   100 * time.Millisecond,
		MaxDelay:    2 * time.Minute,
		Multiplier:  2.5,
		Jitter:      true,
		RetryOn: []core.ErrorType{
			core.ErrorTypeRateLimit,
			core.ErrorTypeTimeout,
			core.ErrorTypeNetwork,
			core.ErrorTypeServer,
		},
	}
	c.SetRetryConfig(config)
	return c
}
