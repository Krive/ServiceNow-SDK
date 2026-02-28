package ratelimit

import "testing"

func TestDetectEndpointType(t *testing.T) {
	tests := []struct {
		path string
		want EndpointType
	}{
		{path: "/table/incident", want: EndpointTypeTable},
		{path: "/api/now/table/incident", want: EndpointTypeTable},
		{path: "/attachment/upload", want: EndpointTypeAttachment},
		{path: "/api/now/attachment/123/file", want: EndpointTypeAttachment},
		{path: "/import/u_staging_table", want: EndpointTypeImport},
		{path: "/api/now/import/u_staging_table", want: EndpointTypeImport},
		{path: "/api/sn_sc/servicecatalog/cart", want: EndpointTypeDefault},
	}

	for _, tt := range tests {
		if got := DetectEndpointType(tt.path); got != tt.want {
			t.Fatalf("unexpected endpoint type for %q: got %q want %q", tt.path, got, tt.want)
		}
	}
}

func TestServiceNowLimiterUpdateConfig(t *testing.T) {
	limiter := NewServiceNowLimiter(DefaultServiceNowConfig())

	limiter.UpdateConfig(ServiceNowLimiterConfig{
		TableRequestsPerSecond:      10,
		AttachmentRequestsPerSecond: 5,
		ImportRequestsPerSecond:     2,
		DefaultRequestsPerSecond:    8,
		TableBurst:                  20,
		AttachmentBurst:             10,
		ImportBurst:                 4,
		DefaultBurst:                12,
	})

	// Basic behavioral assertion: allow path should still be operational after reconfiguration.
	if !limiter.Allow(EndpointTypeDefault) && !limiter.Allow(EndpointTypeTable) {
		t.Fatalf("limiter should allow at least one immediate request after reconfiguration")
	}
}
