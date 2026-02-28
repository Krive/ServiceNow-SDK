package core

import (
	"fmt"
	"net/http"

	"github.com/Krive/ServiceNow-SDK/pkg/types"
)

// Re-export error types for backward compatibility
type ErrorType = types.ErrorType

const (
	ErrorTypeAuthentication = types.ErrorTypeAuthentication
	ErrorTypeAuthorization  = types.ErrorTypeAuthorization
	ErrorTypeRateLimit      = types.ErrorTypeRateLimit
	ErrorTypeValidation     = types.ErrorTypeValidation
	ErrorTypeNotFound       = types.ErrorTypeNotFound
	ErrorTypeTimeout        = types.ErrorTypeTimeout
	ErrorTypeNetwork        = types.ErrorTypeNetwork
	ErrorTypeServer         = types.ErrorTypeServer
	ErrorTypeClient         = types.ErrorTypeClient
	ErrorTypeUnknown        = types.ErrorTypeUnknown
)

// ServiceNowError represents errors from ServiceNow API
type ServiceNowError struct {
	Type       ErrorType `json:"type"`
	Message    string    `json:"message"`
	Code       string    `json:"code"`
	StatusCode int       `json:"status_code"`
	Detail     string    `json:"detail,omitempty"`
	Retryable  bool      `json:"retryable"`
}

func (e *ServiceNowError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("ServiceNow %s error [%d %s]: %s - %s", e.Type, e.StatusCode, e.Code, e.Message, e.Detail)
	}
	return fmt.Sprintf("ServiceNow %s error [%d %s]: %s", e.Type, e.StatusCode, e.Code, e.Message)
}

// IsRetryable returns whether the error is retryable
func (e *ServiceNowError) IsRetryable() bool {
	return e.Retryable
}

// IsRateLimit returns whether the error is a rate limit error
func (e *ServiceNowError) IsRateLimit() bool {
	return e.Type == ErrorTypeRateLimit
}

// IsAuthError returns whether the error is an authentication error
func (e *ServiceNowError) IsAuthError() bool {
	return e.Type == ErrorTypeAuthentication || e.Type == ErrorTypeAuthorization
}

// IsTemporary returns whether the error is temporary
func (e *ServiceNowError) IsTemporary() bool {
	return e.Type == ErrorTypeTimeout || e.Type == ErrorTypeNetwork || e.Type == ErrorTypeRateLimit
}

// GetErrorType returns the error type (implements RetryableError interface)
func (e *ServiceNowError) GetErrorType() ErrorType {
	return e.Type
}

// NewServiceNowError creates a new ServiceNow error with status code classification
func NewServiceNowError(statusCode int, message string) *ServiceNowError {
	code := http.StatusText(statusCode)
	errorType, retryable := classifyError(statusCode)
	
	return &ServiceNowError{
		Type:       errorType,
		Message:    message,
		Code:       code,
		StatusCode: statusCode,
		Retryable:  retryable,
	}
}

// NewServiceNowErrorWithDetail creates a new ServiceNow error with additional detail
func NewServiceNowErrorWithDetail(statusCode int, message, detail string) *ServiceNowError {
	err := NewServiceNowError(statusCode, message)
	err.Detail = detail
	return err
}

// NewAuthenticationError creates a new authentication error
func NewAuthenticationError(message string) *ServiceNowError {
	return &ServiceNowError{
		Type:       ErrorTypeAuthentication,
		Message:    message,
		Code:       "AUTHENTICATION_FAILED",
		StatusCode: http.StatusUnauthorized,
		Retryable:  false,
	}
}

// NewRateLimitError creates a new rate limit error
func NewRateLimitError(message string) *ServiceNowError {
	return &ServiceNowError{
		Type:       ErrorTypeRateLimit,
		Message:    message,
		Code:       "RATE_LIMIT_EXCEEDED",
		StatusCode: http.StatusTooManyRequests,
		Retryable:  true,
	}
}

// NewValidationError creates a new validation error
func NewValidationError(message string) *ServiceNowError {
	return &ServiceNowError{
		Type:       ErrorTypeValidation,
		Message:    message,
		Code:       "VALIDATION_ERROR",
		StatusCode: http.StatusBadRequest,
		Retryable:  false,
	}
}

// NewTimeoutError creates a new timeout error
func NewTimeoutError(message string) *ServiceNowError {
	return &ServiceNowError{
		Type:       ErrorTypeTimeout,
		Message:    message,
		Code:       "REQUEST_TIMEOUT",
		StatusCode: http.StatusRequestTimeout,
		Retryable:  true,
	}
}

// classifyError determines error type and retryability based on status code
func classifyError(statusCode int) (ErrorType, bool) {
	switch {
	case statusCode == http.StatusUnauthorized:
		return ErrorTypeAuthentication, false
	case statusCode == http.StatusForbidden:
		return ErrorTypeAuthorization, false
	case statusCode == http.StatusNotFound:
		return ErrorTypeNotFound, false
	case statusCode == http.StatusTooManyRequests:
		return ErrorTypeRateLimit, true
	case statusCode == http.StatusRequestTimeout:
		return ErrorTypeTimeout, true
	case statusCode >= 400 && statusCode < 500:
		return ErrorTypeClient, false
	case statusCode >= 500:
		return ErrorTypeServer, true
	default:
		return ErrorTypeUnknown, false
	}
}

// IsServiceNowError checks if an error is a ServiceNowError
func IsServiceNowError(err error) (*ServiceNowError, bool) {
	if snErr, ok := err.(*ServiceNowError); ok {
		return snErr, true
	}
	return nil, false
}
