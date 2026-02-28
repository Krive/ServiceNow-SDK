package ratelimit

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Limiter represents a rate limiter interface
type Limiter interface {
	Wait(ctx context.Context) error
	Allow() bool
	Reserve() Reservation
}

// Reservation represents a rate limit reservation
type Reservation interface {
	OK() bool
	Delay() time.Duration
	Cancel()
}

// TokenBucketLimiter implements a token bucket rate limiter
type TokenBucketLimiter struct {
	limiter *rate.Limiter
}

// NewTokenBucketLimiter creates a new token bucket rate limiter
func NewTokenBucketLimiter(requestsPerSecond float64, burst int) *TokenBucketLimiter {
	return &TokenBucketLimiter{
		limiter: rate.NewLimiter(rate.Limit(requestsPerSecond), burst),
	}
}

// Wait blocks until the rate limiter allows a request
func (t *TokenBucketLimiter) Wait(ctx context.Context) error {
	return t.limiter.Wait(ctx)
}

// Allow returns whether a request can be made immediately
func (t *TokenBucketLimiter) Allow() bool {
	return t.limiter.Allow()
}

// Reserve reserves a token for a future request
func (t *TokenBucketLimiter) Reserve() Reservation {
	return &tokenReservation{
		reservation: t.limiter.Reserve(),
	}
}

type tokenReservation struct {
	reservation *rate.Reservation
}

func (r *tokenReservation) OK() bool {
	return r.reservation.OK()
}

func (r *tokenReservation) Delay() time.Duration {
	return r.reservation.Delay()
}

func (r *tokenReservation) Cancel() {
	r.reservation.Cancel()
}

// ServiceNowLimiter provides rate limiting specifically for ServiceNow API
type ServiceNowLimiter struct {
	// Different limits for different endpoints
	tableLimiter      Limiter
	attachmentLimiter Limiter
	importLimiter     Limiter
	defaultLimiter    Limiter
	
	mu sync.RWMutex
}

// ServiceNowLimiterConfig holds configuration for ServiceNow rate limiting
type ServiceNowLimiterConfig struct {
	// Requests per second for different endpoint types
	TableRequestsPerSecond      float64
	AttachmentRequestsPerSecond float64
	ImportRequestsPerSecond     float64
	DefaultRequestsPerSecond    float64
	
	// Burst allowances
	TableBurst      int
	AttachmentBurst int
	ImportBurst     int
	DefaultBurst    int
}

// DefaultServiceNowConfig returns default rate limiting configuration for ServiceNow
// Based on ServiceNow's documented rate limits
func DefaultServiceNowConfig() ServiceNowLimiterConfig {
	return ServiceNowLimiterConfig{
		// Conservative defaults based on ServiceNow limits
		TableRequestsPerSecond:      5.0,  // 5 requests per second for table operations
		AttachmentRequestsPerSecond: 2.0,  // 2 requests per second for attachments (larger payloads)
		ImportRequestsPerSecond:     1.0,  // 1 request per second for imports (heavy operations)
		DefaultRequestsPerSecond:    3.0,  // 3 requests per second for other operations
		
		// Burst allowances
		TableBurst:      10,
		AttachmentBurst: 5,
		ImportBurst:     2,
		DefaultBurst:    6,
	}
}

// NewServiceNowLimiter creates a new ServiceNow-specific rate limiter
func NewServiceNowLimiter(config ServiceNowLimiterConfig) *ServiceNowLimiter {
	return &ServiceNowLimiter{
		tableLimiter:      NewTokenBucketLimiter(config.TableRequestsPerSecond, config.TableBurst),
		attachmentLimiter: NewTokenBucketLimiter(config.AttachmentRequestsPerSecond, config.AttachmentBurst),
		importLimiter:     NewTokenBucketLimiter(config.ImportRequestsPerSecond, config.ImportBurst),
		defaultLimiter:    NewTokenBucketLimiter(config.DefaultRequestsPerSecond, config.DefaultBurst),
	}
}

// EndpointType represents different ServiceNow endpoint types
type EndpointType string

const (
	EndpointTypeTable      EndpointType = "table"
	EndpointTypeAttachment EndpointType = "attachment"
	EndpointTypeImport     EndpointType = "import"
	EndpointTypeDefault    EndpointType = "default"
)

// Wait waits for permission to make a request to the specified endpoint type
func (s *ServiceNowLimiter) Wait(ctx context.Context, endpointType EndpointType) error {
	limiter := s.getLimiter(endpointType)
	return limiter.Wait(ctx)
}

// Allow checks if a request can be made immediately to the specified endpoint type
func (s *ServiceNowLimiter) Allow(endpointType EndpointType) bool {
	limiter := s.getLimiter(endpointType)
	return limiter.Allow()
}

// Reserve reserves permission for a future request to the specified endpoint type
func (s *ServiceNowLimiter) Reserve(endpointType EndpointType) Reservation {
	limiter := s.getLimiter(endpointType)
	return limiter.Reserve()
}

// getLimiter returns the appropriate limiter for the endpoint type
func (s *ServiceNowLimiter) getLimiter(endpointType EndpointType) Limiter {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	switch endpointType {
	case EndpointTypeTable:
		return s.tableLimiter
	case EndpointTypeAttachment:
		return s.attachmentLimiter
	case EndpointTypeImport:
		return s.importLimiter
	default:
		return s.defaultLimiter
	}
}

// UpdateConfig updates the rate limiting configuration
func (s *ServiceNowLimiter) UpdateConfig(config ServiceNowLimiterConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	s.tableLimiter = NewTokenBucketLimiter(config.TableRequestsPerSecond, config.TableBurst)
	s.attachmentLimiter = NewTokenBucketLimiter(config.AttachmentRequestsPerSecond, config.AttachmentBurst)
	s.importLimiter = NewTokenBucketLimiter(config.ImportRequestsPerSecond, config.ImportBurst)
	s.defaultLimiter = NewTokenBucketLimiter(config.DefaultRequestsPerSecond, config.DefaultBurst)
}

// DetectEndpointType attempts to determine the endpoint type from a URL path
func DetectEndpointType(path string) EndpointType {
	switch {
	case contains(path, "/table/") || contains(path, "/now/table/"):
		return EndpointTypeTable
	case contains(path, "/attachment") || contains(path, "/now/attachment"):
		return EndpointTypeAttachment
	case contains(path, "/import") || contains(path, "/now/import"):
		return EndpointTypeImport
	default:
		return EndpointTypeDefault
	}
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || 
		(len(s) > len(substr) && 
			(s[:len(substr)] == substr || 
			 s[len(s)-len(substr):] == substr ||
			 indexOf(s, substr) >= 0)))
}

// indexOf returns the index of substr in s, or -1 if not found
func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// RateLimitError represents a rate limit exceeded error
type RateLimitError struct {
	Message   string
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("rate limit exceeded: %s (retry after %v)", e.Message, e.RetryAfter)
}

// NewRateLimitError creates a new rate limit error
func NewRateLimitError(message string, retryAfter time.Duration) *RateLimitError {
	return &RateLimitError{
		Message:   message,
		RetryAfter: retryAfter,
	}
}