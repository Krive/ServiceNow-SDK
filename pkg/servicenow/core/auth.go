package core

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
)

// AuthProvider defines the interface for authentication methods
type AuthProvider interface {
	Apply(client *resty.Client) error
	IsExpired() bool
	Refresh() error // For refreshable auth methods
}

// TokenStorage defines interface for token persistence
type TokenStorage interface {
	Save(key string, token *OAuthToken) error
	Load(key string) (*OAuthToken, error)
	Delete(key string) error
}

// FileTokenStorage implements token storage using local files
type FileTokenStorage struct {
	directory string
}

// NewFileTokenStorage creates a new file-based token storage
func NewFileTokenStorage(directory string) *FileTokenStorage {
	if directory == "" {
		// Default to user's home directory/.servicenowtoolkit/tokens
		homeDir, _ := os.UserHomeDir()
		directory = filepath.Join(homeDir, ".servicenowtoolkit", "tokens")
	}

	// Ensure directory exists
	os.MkdirAll(directory, 0700)

	return &FileTokenStorage{directory: directory}
}

func (f *FileTokenStorage) Save(key string, token *OAuthToken) error {
	filename := filepath.Join(f.directory, key+".json")
	data, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}

	return os.WriteFile(filename, data, 0600) // Read/write for owner only
}

func (f *FileTokenStorage) Load(key string) (*OAuthToken, error) {
	filename := filepath.Join(f.directory, key+".json")
	data, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No token found
		}
		return nil, fmt.Errorf("failed to read token file: %w", err)
	}

	var token OAuthToken
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token: %w", err)
	}

	return &token, nil
}

func (f *FileTokenStorage) Delete(key string) error {
	filename := filepath.Join(f.directory, key+".json")
	err := os.Remove(filename)
	if os.IsNotExist(err) {
		return nil // Already deleted
	}
	return err
}

// BasicAuth handles username/password authentication
type BasicAuth struct {
	username string
	password string
}

func NewBasicAuth(username, password string) *BasicAuth {
	return &BasicAuth{
		username: username,
		password: password,
	}
}

func (b *BasicAuth) Apply(client *resty.Client) error {
	auth := base64.StdEncoding.EncodeToString([]byte(b.username + ":" + b.password))
	client.SetHeader("Authorization", "Basic "+auth)
	return nil
}

func (b *BasicAuth) IsExpired() bool {
	return false // Basic Auth doesn't expire
}

func (b *BasicAuth) Refresh() error {
	return nil // Basic Auth doesn't need refresh
}

// OAuthClientCredentials handles OAuth 2.0 client credentials flow
type OAuthClientCredentials struct {
	clientID     string
	clientSecret string
	instanceURL  string
	token        *OAuthToken
	expiresAt    time.Time
	storage      TokenStorage
	storageKey   string
	mu           sync.Mutex
	username     string
	password     string
}

// OAuthAuthorizationCode handles OAuth 2.0 authorization code flow with refresh tokens
type OAuthAuthorizationCode struct {
	clientID     string
	clientSecret string
	instanceURL  string
	token        *OAuthToken
	expiresAt    time.Time
	storage      TokenStorage
	storageKey   string
	mu           sync.Mutex
}

func NewOAuthClientCredentials(instanceURL, clientID, clientSecret string) *OAuthClientCredentials {
	storage := NewFileTokenStorage("")
	storageKey := fmt.Sprintf("oauth_cc_%s_%s", instanceURL, clientID)

	oauth := &OAuthClientCredentials{
		clientID:     clientID,
		clientSecret: clientSecret,
		instanceURL:  instanceURL,
		storage:      storage,
		storageKey:   storageKey,
	}

	// Try to load existing token
	if token, err := storage.Load(storageKey); err == nil && token != nil {
		oauth.token = token
		oauth.expiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	}

	return oauth
}

// NewOAuthClientCredentialsWithStorage creates OAuth client credentials with custom storage
func NewOAuthClientCredentialsWithStorage(instanceURL, clientID, clientSecret string, storage TokenStorage) *OAuthClientCredentials {
	storageKey := fmt.Sprintf("oauth_cc_%s_%s", instanceURL, clientID)

	oauth := &OAuthClientCredentials{
		clientID:     clientID,
		clientSecret: clientSecret,
		instanceURL:  instanceURL,
		storage:      storage,
		storageKey:   storageKey,
	}

	// Try to load existing token
	if token, err := storage.Load(storageKey); err == nil && token != nil {
		oauth.token = token
		oauth.expiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	}

	return oauth
}

// NewOAuthAuthorizationCode creates OAuth authorization code flow auth
func NewOAuthAuthorizationCode(instanceURL, clientID, clientSecret string, refreshToken string) *OAuthAuthorizationCode {
	storage := NewFileTokenStorage("")
	storageKey := fmt.Sprintf("oauth_ac_%s_%s", instanceURL, clientID)

	oauth := &OAuthAuthorizationCode{
		clientID:     clientID,
		clientSecret: clientSecret,
		instanceURL:  instanceURL,
		storage:      storage,
		storageKey:   storageKey,
	}

	// Try to load existing token first
	if token, err := storage.Load(storageKey); err == nil && token != nil {
		oauth.token = token
		oauth.expiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	} else if refreshToken != "" {
		// Set initial refresh token if provided
		oauth.token = &OAuthToken{
			RefreshToken: refreshToken,
		}
	}

	return oauth
}

// NewOAuthAuthorizationCodeWithStorage creates OAuth authorization code flow with custom storage
func NewOAuthAuthorizationCodeWithStorage(instanceURL, clientID, clientSecret string, refreshToken string, storage TokenStorage) *OAuthAuthorizationCode {
	storageKey := fmt.Sprintf("oauth_ac_%s_%s", instanceURL, clientID)

	oauth := &OAuthAuthorizationCode{
		clientID:     clientID,
		clientSecret: clientSecret,
		instanceURL:  instanceURL,
		storage:      storage,
		storageKey:   storageKey,
	}

	// Try to load existing token first
	if token, err := storage.Load(storageKey); err == nil && token != nil {
		oauth.token = token
		oauth.expiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	} else if refreshToken != "" {
		// Set initial refresh token if provided
		oauth.token = &OAuthToken{
			RefreshToken: refreshToken,
		}
	}

	return oauth
}

func (o *OAuthClientCredentials) Apply(client *resty.Client) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.IsExpired() {
		if err := o.Refresh(); err != nil {
			return fmt.Errorf("failed to refresh token: %w", err)
		}
	}

	if o.token == nil {
		return fmt.Errorf("no token available")
	}

	client.SetHeader("Authorization", fmt.Sprintf("%s %s", o.token.TokenType, o.token.AccessToken))
	return nil
}

func (o *OAuthClientCredentials) IsExpired() bool {
	return o.token == nil || time.Now().After(o.expiresAt.Add(-10*time.Second)) // Buffer for safety
}

func (o *OAuthClientCredentials) Refresh() error {
	// Create a temporary client for token refresh
	tempClient := resty.New()

	resp, err := tempClient.R().
		SetFormData(map[string]string{
			"grant_type":    "client_credentials",
			"client_id":     o.clientID,
			"client_secret": o.clientSecret,
		}).
		Post(o.instanceURL + "/oauth_token.do")

	if err != nil {
		return err
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("OAuth request failed: %s - %s", resp.Status(), string(resp.Body()))
	}

	var token OAuthToken
	if err := json.Unmarshal(resp.Body(), &token); err != nil {
		return fmt.Errorf("failed to unmarshal OAuth token: %w", err)
	}

	o.token = &token
	o.expiresAt = time.Now().Add(time.Duration(o.token.ExpiresIn) * time.Second)

	// Save token to storage
	if o.storage != nil {
		if err := o.storage.Save(o.storageKey, o.token); err != nil {
			// Log but don't fail - storage is optional
			fmt.Printf("Warning: failed to save token to storage: %v\n", err)
		}
	}

	return nil
}

// OAuth Authorization Code methods
func (o *OAuthAuthorizationCode) Apply(client *resty.Client) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.IsExpired() {
		if err := o.Refresh(); err != nil {
			return fmt.Errorf("failed to refresh token: %w", err)
		}
	}

	if o.token == nil || o.token.AccessToken == "" {
		return fmt.Errorf("no access token available")
	}

	tokenType := o.token.TokenType
	if tokenType == "" {
		tokenType = "Bearer" // Default to Bearer if not specified
	}

	client.SetHeader("Authorization", fmt.Sprintf("%s %s", tokenType, o.token.AccessToken))
	return nil
}

func (o *OAuthAuthorizationCode) IsExpired() bool {
	return o.token == nil || o.token.AccessToken == "" || time.Now().After(o.expiresAt.Add(-10*time.Second))
}

func (o *OAuthAuthorizationCode) Refresh() error {
	if o.token == nil || o.token.RefreshToken == "" {
		return fmt.Errorf("no refresh token available")
	}

	// Create a temporary client for token refresh
	tempClient := resty.New()

	resp, err := tempClient.R().
		SetFormData(map[string]string{
			"grant_type":    "refresh_token",
			"refresh_token": o.token.RefreshToken,
			"client_id":     o.clientID,
			"client_secret": o.clientSecret,
		}).
		Post(o.instanceURL + "/oauth_token.do")

	if err != nil {
		return fmt.Errorf("refresh token request failed: %w", err)
	}

	if !resp.IsSuccess() {
		return fmt.Errorf("refresh token request failed: %s - %s", resp.Status(), string(resp.Body()))
	}

	var newToken OAuthToken
	if err := json.Unmarshal(resp.Body(), &newToken); err != nil {
		return fmt.Errorf("failed to unmarshal refresh token response: %w", err)
	}

	// If no new refresh token is provided, keep the old one
	if newToken.RefreshToken == "" {
		newToken.RefreshToken = o.token.RefreshToken
	}

	o.token = &newToken
	o.expiresAt = time.Now().Add(time.Duration(o.token.ExpiresIn) * time.Second)

	// Save token to storage
	if o.storage != nil {
		if err := o.storage.Save(o.storageKey, o.token); err != nil {
			// Log but don't fail - storage is optional
			fmt.Printf("Warning: failed to save token to storage: %v\n", err)
		}
	}

	return nil
}
