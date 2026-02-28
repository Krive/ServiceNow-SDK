package types

// RetryableError interface defines errors that can be retried
type RetryableError interface {
	error
	IsRetryable() bool
	GetErrorType() ErrorType
}