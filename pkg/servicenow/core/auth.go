package core

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

// MemoryTokenStorage keeps OAuth tokens in-memory only (no persistence on disk).
type MemoryTokenStorage struct {
	mu     sync.RWMutex
	tokens map[string]storedOAuthToken
}

type storedOAuthToken struct {
	Token     OAuthToken `json:"token"`
	ExpiresAt time.Time  `json:"expires_at,omitempty"`
}

// NewFileTokenStorage creates a new file-based token storage
func NewFileTokenStorage(directory string) *FileTokenStorage {
	if directory == "" {
		// Default to user's home directory/.servicenowtoolkit/tokens
		homeDir, err := os.UserHomeDir()
		if err != nil || homeDir == "" {
			homeDir = os.TempDir()
		}
		directory = filepath.Join(homeDir, ".servicenowtoolkit", "tokens")
	}

	// Ensure directory exists
	_ = os.MkdirAll(directory, 0700)

	return &FileTokenStorage{directory: directory}
}

// NewMemoryTokenStorage creates a token store that does not write to disk.
func NewMemoryTokenStorage() *MemoryTokenStorage {
	return &MemoryTokenStorage{
		tokens: make(map[string]storedOAuthToken),
	}
}

func (f *FileTokenStorage) Save(key string, token *OAuthToken) error {
	filename := f.tokenFilePath(key)
	stored := storedOAuthToken{
		Token: *token,
	}
	if token.ExpiresIn > 0 {
		stored.ExpiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	}

	data, err := json.Marshal(stored)
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}

	return os.WriteFile(filename, data, 0600) // Read/write for owner only
}

func (f *FileTokenStorage) Load(key string) (*OAuthToken, error) {
	filename := f.tokenFilePath(key)
	data, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No token found
		}
		return nil, fmt.Errorf("failed to read token file: %w", err)
	}

	var stored storedOAuthToken
	if err := json.Unmarshal(data, &stored); err == nil && (stored.Token.AccessToken != "" || stored.Token.RefreshToken != "" || !stored.ExpiresAt.IsZero()) {
		token := stored.Token
		if !stored.ExpiresAt.IsZero() {
			remaining := time.Until(stored.ExpiresAt)
			if remaining <= 0 {
				token.ExpiresIn = 0
			} else {
				token.ExpiresIn = int(remaining.Round(time.Second) / time.Second)
			}
		}
		return &token, nil
	}

	// Backward compatibility with plain OAuthToken storage format.
	var token OAuthToken
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token: %w", err)
	}

	return &token, nil
}

func (f *FileTokenStorage) Delete(key string) error {
	filename := f.tokenFilePath(key)
	err := os.Remove(filename)
	if os.IsNotExist(err) {
		return nil // Already deleted
	}
	return err
}

func (f *FileTokenStorage) tokenFilePath(key string) string {
	hash := sha256.Sum256([]byte(key))
	return filepath.Join(f.directory, hex.EncodeToString(hash[:])+".json")
}

func (m *MemoryTokenStorage) Save(key string, token *OAuthToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	stored := storedOAuthToken{Token: *token}
	if token.ExpiresIn > 0 {
		stored.ExpiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	}
	m.tokens[key] = stored
	return nil
}

func (m *MemoryTokenStorage) Load(key string) (*OAuthToken, error) {
	m.mu.RLock()
	stored, ok := m.tokens[key]
	m.mu.RUnlock()
	if !ok {
		return nil, nil
	}

	token := stored.Token
	if !stored.ExpiresAt.IsZero() {
		remaining := time.Until(stored.ExpiresAt)
		if remaining <= 0 {
			token.ExpiresIn = 0
		} else {
			token.ExpiresIn = int(remaining.Round(time.Second) / time.Second)
		}
	}
	return &token, nil
}

func (m *MemoryTokenStorage) Delete(key string) error {
	m.mu.Lock()
	delete(m.tokens, key)
	m.mu.Unlock()
	return nil
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

	tokenType := o.token.TokenType
	if tokenType == "" {
		tokenType = "Bearer"
	}
	client.SetHeader("Authorization", fmt.Sprintf("%s %s", tokenType, o.token.AccessToken))
	return nil
}

func (o *OAuthClientCredentials) IsExpired() bool {
	return o.token == nil || time.Now().After(o.expiresAt.Add(-10*time.Second)) // Buffer for safety
}

func (o *OAuthClientCredentials) Refresh() error {
	// Create a temporary client for token refresh
	tempClient := resty.New()
	tempClient.SetTimeout(30 * time.Second)

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
		_ = o.storage.Save(o.storageKey, o.token)
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
	tempClient.SetTimeout(30 * time.Second)

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
		_ = o.storage.Save(o.storageKey, o.token)
	}

	return nil
}
