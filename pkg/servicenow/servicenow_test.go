package servicenow

import "testing"

func TestNewClientEnforcesHTTPSByDefault(t *testing.T) {
	_, err := NewClient(Config{
		InstanceURL: "http://example.service-now.com",
		Username:    "user",
		Password:    "pass",
	})
	if err == nil {
		t.Fatalf("expected insecure URL to be rejected by default")
	}
}

func TestNewClientAllowsHTTPWhenExplicitlyEnabled(t *testing.T) {
	client, err := NewClient(Config{
		InstanceURL:       "http://example.service-now.com",
		AllowInsecureHTTP: true,
		Username:          "user",
		Password:          "pass",
	})
	if err != nil {
		t.Fatalf("expected insecure URL to be accepted when explicitly enabled: %v", err)
	}
	if client == nil || client.Core() == nil {
		t.Fatalf("expected client to be created")
	}
	if client.Core().InstanceURL != "http://example.service-now.com" {
		t.Fatalf("unexpected normalized instance URL: %q", client.Core().InstanceURL)
	}
}
