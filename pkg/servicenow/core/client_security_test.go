package core

import "testing"

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
