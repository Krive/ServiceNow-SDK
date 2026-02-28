package retry

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Krive/ServiceNow-SDK/pkg/types"
)

type wrappedRetryableError struct{}

func (wrappedRetryableError) Error() string                 { return "wrapped retryable" }
func (wrappedRetryableError) IsRetryable() bool             { return true }
func (wrappedRetryableError) GetErrorType() types.ErrorType { return types.ErrorTypeServer }

func TestDoRetriesWrappedRetryableErrors(t *testing.T) {
	attempts := 0
	cfg := Config{
		MaxAttempts: 2,
		BaseDelay:   time.Millisecond,
		MaxDelay:    time.Millisecond,
		Multiplier:  1,
		Jitter:      false,
		RetryOn:     []types.ErrorType{types.ErrorTypeServer},
	}

	err := Do(context.Background(), cfg, func() error {
		attempts++
		return fmt.Errorf("wrapped: %w", wrappedRetryableError{})
	})

	if err == nil {
		t.Fatal("expected error")
	}
	if attempts != 2 {
		t.Fatalf("expected 2 attempts, got %d", attempts)
	}
}
