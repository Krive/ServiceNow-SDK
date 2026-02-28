package types

// ErrorType represents different categories of errors
type ErrorType string

const (
	ErrorTypeAuthentication ErrorType = "authentication"
	ErrorTypeAuthorization  ErrorType = "authorization"
	ErrorTypeRateLimit      ErrorType = "rate_limit"
	ErrorTypeValidation     ErrorType = "validation"
	ErrorTypeNotFound       ErrorType = "not_found"
	ErrorTypeTimeout        ErrorType = "timeout"
	ErrorTypeNetwork        ErrorType = "network"
	ErrorTypeServer         ErrorType = "server"
	ErrorTypeClient         ErrorType = "client"
	ErrorTypeUnknown        ErrorType = "unknown"
)