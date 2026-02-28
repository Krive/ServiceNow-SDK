package core

import (
	"strconv"
)

// Response wraps ServiceNow API responses
type Response struct {
	Result interface{} `json:"result"`
	Error  string      `json:"error,omitempty"`
}

// OAuthToken holds OAuth token response data
type OAuthToken struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope"`
}

type DisplayValueOptions string

const (
	DisplayTrue  DisplayValueOptions = "true"
	DisplayFalse DisplayValueOptions = "false"
	DisplayAll   DisplayValueOptions = "all"
)

// ColumnMetadata represents field details from schema
type ColumnMetadata struct {
	Name         string `json:"name"`
	Label        string `json:"label"`
	Type         string `json:"type"`
	MaxLength    int    `json:"max_length,omitempty"`
	DefaultValue string `json:"default_value,omitempty"`
	Mandatory    bool   `json:"mandatory,omitempty"`
	ReadOnly     bool   `json:"read_only,omitempty"`
	Unique       bool   `json:"unique,omitempty"`
	Reference    string `json:"reference,omitempty"`
	Choice       bool   `json:"choice,omitempty"`
	Calculated   bool   `json:"calculated,omitempty"`
	// Add more fields as needed (e.g., "reference_qualifier", "element")
}

// SchemaResponse wraps the schema endpoint response
type SchemaResponse struct {
	Columns []ColumnMetadata `json:"columns"` // Adjust key if response differs (e.g., "fields")
}

// parseInt helper
func parseInt(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}
