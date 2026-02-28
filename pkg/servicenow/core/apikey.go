package core

import (
	"fmt"

	"github.com/go-resty/resty/v2"
)

// APIKeyAuth handles ServiceNow API key authentication
type APIKeyAuth struct {
	apiKey string
}

// NewAPIKeyAuth creates a new API key authentication provider
func NewAPIKeyAuth(apiKey string) *APIKeyAuth {
	return &APIKeyAuth{
		apiKey: apiKey,
	}
}

func (a *APIKeyAuth) Apply(client *resty.Client) error {
	if a.apiKey == "" {
		return fmt.Errorf("API key is required")
	}

	// ServiceNow API key authentication uses X-Api-Key header
	client.SetHeader("x-sn-apikey", a.apiKey)
	return nil
}

func (a *APIKeyAuth) IsExpired() bool {
	return false // API keys don't expire (but can be revoked)
}

func (a *APIKeyAuth) Refresh() error {
	return nil // API keys don't need refresh
}
