package core

import (
	"testing"
	"time"
)

func TestValidateAndNormalizeInstanceURLRequiresHTTPSByDefault(t *testing.T) {
	if _, err := validateAndNormalizeInstanceURL("http://example.service-now.com", false); err == nil {
		t.Fatalf("expected insecure http URL to be rejected")
	}
}

func TestValidateAndNormalizeInstanceURLAllowsHTTPWhenConfigured(t *testing.T) {
	got, err := validateAndNormalizeInstanceURL("http://example.service-now.com/path", true)
	if err != nil {
		t.Fatalf("expected insecure http URL to be accepted when configured: %v", err)
	}
	if got != "http://example.service-now.com" {
		t.Fatalf("unexpected normalized URL: %q", got)
	}
}

func TestNewClientBasicAuthWithOptionsEnforcesHTTPS(t *testing.T) {
	if _, err := NewClientBasicAuth("http://example.service-now.com", "user", "pass"); err == nil {
		t.Fatalf("expected insecure URL rejection")
	}

	client, err := NewClientBasicAuthWithOptions("http://example.service-now.com", "user", "pass", ClientOptions{
		AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatalf("expected insecure URL acceptance with explicit option: %v", err)
	}
	if client.InstanceURL != "http://example.service-now.com" {
		t.Fatalf("unexpected normalized instance URL: %q", client.InstanceURL)
	}
}

func TestResolveRootRequestURLBlocksCrossHostByDefault(t *testing.T) {
	client := &Client{
		InstanceURL: "https://example.service-now.com",
	}

	if _, err := client.resolveRootRequestURL("https://evil.example.com/api/now/table/incident"); err == nil {
		t.Fatalf("expected cross-host absolute URL to be blocked")
	}
}

func TestResolveRootRequestURLAllowsCrossHostWhenConfigured(t *testing.T) {
	client := &Client{
		InstanceURL:                "https://example.service-now.com",
		allowCrossHostRootRequests: true,
	}

	got, err := client.resolveRootRequestURL("https://evil.example.com/api/now/table/incident")
	if err != nil {
		t.Fatalf("expected cross-host absolute URL to be allowed when configured: %v", err)
	}
	if got != "https://evil.example.com/api/now/table/incident" {
		t.Fatalf("unexpected resolved URL: %q", got)
	}
}

func TestResolveRootRequestURLAcceptsSameHostDifferentPortNotation(t *testing.T) {
	client := &Client{
		InstanceURL: "https://example.service-now.com:443",
	}

	got, err := client.resolveRootRequestURL("https://example.service-now.com/api/now/table/incident")
	if err != nil {
		t.Fatalf("expected same-host absolute URL to be accepted: %v", err)
	}
	if got == "" {
		t.Fatalf("expected resolved URL, got empty string")
	}
}

func TestNewClientOAuthWithStorageUsesNormalizedInstanceURLForTokenEndpoint(t *testing.T) {
	auth := &OAuthClientCredentials{
		clientID:     "client-id",
		clientSecret: "client-secret",
		instanceURL:  "https://example.service-now.com/some/path",
		token: &OAuthToken{
			AccessToken: "token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		},
		expiresAt: time.Now().Add(1 * time.Hour),
	}

	client, err := newClientWithOptions("https://example.service-now.com/some/path", auth, ClientOptions{})
	if err != nil {
		t.Fatalf("failed to create OAuth client: %v", err)
	}

	oauth, ok := client.Auth.(*OAuthClientCredentials)
	if !ok {
		t.Fatalf("expected OAuth client credentials auth provider, got %T", client.Auth)
	}
	if oauth.instanceURL != "https://example.service-now.com" {
		t.Fatalf("expected normalized OAuth instance URL, got %q", oauth.instanceURL)
	}
}

func TestNewClientOAuthRefreshWithStorageUsesNormalizedInstanceURLForTokenEndpoint(t *testing.T) {
	auth := &OAuthAuthorizationCode{
		clientID:     "client-id",
		clientSecret: "client-secret",
		instanceURL:  "https://example.service-now.com/some/path",
		token: &OAuthToken{
			AccessToken:  "token",
			RefreshToken: "refresh-token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		},
		expiresAt: time.Now().Add(1 * time.Hour),
	}

	client, err := newClientWithOptions("https://example.service-now.com/some/path", auth, ClientOptions{})
	if err != nil {
		t.Fatalf("failed to create OAuth refresh client: %v", err)
	}

	oauth, ok := client.Auth.(*OAuthAuthorizationCode)
	if !ok {
		t.Fatalf("expected OAuth authorization code auth provider, got %T", client.Auth)
	}
	if oauth.instanceURL != "https://example.service-now.com" {
		t.Fatalf("expected normalized OAuth instance URL, got %q", oauth.instanceURL)
	}
}
