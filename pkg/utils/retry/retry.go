package retry

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"time"

	"github.com/Krive/ServiceNow-SDK/pkg/types"
)

// Config holds retry configuration
type Config struct {
	MaxAttempts   int           // Maximum number of retry attempts
	BaseDelay     time.Duration // Base delay between retries
	MaxDelay      time.Duration // Maximum delay between retries
	Multiplier    float64       // Multiplier for exponential backoff
	Jitter        bool          // Add random jitter to delays
	RetryOn       []types.ErrorType // Error types to retry on
}

// DefaultConfig returns a sensible default retry configuration
func DefaultConfig() Config {
	return Config{
		MaxAttempts: 3,
		BaseDelay:   100 * time.Millisecond,
		MaxDelay:    30 * time.Second,
		Multiplier:  2.0,
		Jitter:      true,
		RetryOn: []types.ErrorType{
			types.ErrorTypeRateLimit,
			types.ErrorTypeTimeout,
			types.ErrorTypeNetwork,
			types.ErrorTypeServer,
		},
	}
}

// ServiceNowRetryConfig returns retry configuration optimized for ServiceNow API
func ServiceNowRetryConfig() Config {
	return Config{
		MaxAttempts: 5,
		BaseDelay:   500 * time.Millisecond,
		MaxDelay:    60 * time.Second,
		Multiplier:  2.0,
		Jitter:      true,
		RetryOn: []types.ErrorType{
			types.ErrorTypeRateLimit,
			types.ErrorTypeTimeout,
			types.ErrorTypeServer,
		},
	}
}

// RetryableFunc is a function that can be retried
type RetryableFunc func() error

// RetryableFuncWithResult is a function that returns a result and can be retried
type RetryableFuncWithResult[T any] func() (T, error)

// Do executes a function with retry logic
func Do(ctx context.Context, config Config, fn RetryableFunc) error {
	var lastErr error
	
	for attempt := 0; attempt < config.MaxAttempts; attempt++ {
		// Execute the function
		err := fn()
		if err == nil {
			return nil // Success
		}
		
		lastErr = err
		
		// Check if we should retry this error
		if !shouldRetry(err, config.RetryOn) {
			return err // Not retryable
		}
		
		// Don't sleep after the last attempt
		if attempt == config.MaxAttempts-1 {
			break
		}
		
		// Calculate delay
		delay := calculateDelay(attempt, config)
		
		// Wait with context cancellation support
		select {
		case <-ctx.Done():
			return fmt.Errorf("retry cancelled: %w", ctx.Err())
		case <-time.After(delay):
			// Continue to next attempt
		}
	}
	
	return fmt.Errorf("max retry attempts (%d) exceeded: %w", config.MaxAttempts, lastErr)
}

// DoWithResult executes a function with retry logic and returns a result
func DoWithResult[T any](ctx context.Context, config Config, fn RetryableFuncWithResult[T]) (T, error) {
	var lastErr error
	var result T
	
	for attempt := 0; attempt < config.MaxAttempts; attempt++ {
		// Execute the function
		res, err := fn()
		if err == nil {
			return res, nil // Success
		}
		
		lastErr = err
		result = res // Keep the last result (might be partial)
		
		// Check if we should retry this error
		if !shouldRetry(err, config.RetryOn) {
			return result, err // Not retryable
		}
		
		// Don't sleep after the last attempt
		if attempt == config.MaxAttempts-1 {
			break
		}
		
		// Calculate delay
		delay := calculateDelay(attempt, config)
		
		// Wait with context cancellation support
		select {
		case <-ctx.Done():
			return result, fmt.Errorf("retry cancelled: %w", ctx.Err())
		case <-time.After(delay):
			// Continue to next attempt
		}
	}
	
	return result, fmt.Errorf("max retry attempts (%d) exceeded: %w", config.MaxAttempts, lastErr)
}

// shouldRetry determines if an error should be retried
func shouldRetry(err error, retryableTypes []types.ErrorType) bool {
	// Check if error implements RetryableError interface
	if retryErr, ok := err.(types.RetryableError); ok {
		// Check if error is explicitly retryable
		if !retryErr.IsRetryable() {
			return false
		}
		
		// Check if error type is in the retryable list
		for _, retryableType := range retryableTypes {
			if retryErr.GetErrorType() == retryableType {
				return true
			}
		}
	}
	
	return false
}

// calculateDelay calculates the delay for exponential backoff with jitter
func calculateDelay(attempt int, config Config) time.Duration {
	// Calculate exponential backoff delay
	delay := float64(config.BaseDelay) * math.Pow(config.Multiplier, float64(attempt))
	
	// Cap at max delay
	if delay > float64(config.MaxDelay) {
		delay = float64(config.MaxDelay)
	}
	
	// Add jitter if enabled
	if config.Jitter {
		// Add random jitter up to �25% of the delay
		jitter := delay * 0.25 * (rand.Float64()*2 - 1)
		delay += jitter
		
		// Ensure delay is not negative
		if delay < 0 {
			delay = float64(config.BaseDelay)
		}
	}
	
	return time.Duration(delay)
}

// RetryableError wraps an error to indicate it should be retried
type RetryableError struct {
	Err error
}

func (r *RetryableError) Error() string {
	return fmt.Sprintf("retryable error: %v", r.Err)
}

func (r *RetryableError) Unwrap() error {
	return r.Err
}

// NewRetryableError creates a new retryable error
func NewRetryableError(err error) *RetryableError {
	return &RetryableError{Err: err}
}

// IsRetryableError checks if an error is retryable
func IsRetryableError(err error) bool {
	if err == nil {
		return false
	}
	
	// Check if error implements RetryableError interface
	if retryErr, ok := err.(types.RetryableError); ok {
		return retryErr.IsRetryable()
	}
	
	return false
}