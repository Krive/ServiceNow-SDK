package batch

import (
	"encoding/base64"
	"testing"
)

func TestParseBatchResponseDecodesServicedResults(t *testing.T) {
	encodedBody := base64.StdEncoding.EncodeToString([]byte(`{"result":{"sys_id":"abc123"}}`))
	response := &BatchResponse{
		BatchRequestID: "batch_1",
		ServicedRequests: []ServicedRequest{
			{
				ID:            "req1",
				StatusCode:    200,
				StatusText:    "OK",
				Body:          encodedBody,
				ExecutionTime: 12,
			},
		},
		UnservicedRequests: []UnservicedRequest{
			{
				ID:          "req2",
				StatusCode:  404,
				StatusText:  "Not Found",
				ErrorDetail: "missing",
			},
		},
	}

	result, err := parseBatchResponse(response)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	if result.TotalRequests != 2 || result.SuccessfulRequests != 1 || result.FailedRequests != 1 {
		t.Fatalf("unexpected aggregate counts: %+v", result)
	}

	if got, ok := result.GetResult("req1"); !ok || got.StatusCode != 200 {
		t.Fatalf("expected successful result for req1, got=%+v exists=%t", got, ok)
	}

	if got, ok := result.GetError("req2"); !ok || got.StatusCode != 404 {
		t.Fatalf("expected failed result for req2, got=%+v exists=%t", got, ok)
	}
}

func TestParseBatchResponseFailsOnInvalidBase64(t *testing.T) {
	response := &BatchResponse{
		BatchRequestID: "batch_1",
		ServicedRequests: []ServicedRequest{
			{
				ID:   "req1",
				Body: "!!!not-base64!!!",
			},
		},
	}

	if _, err := parseBatchResponse(response); err == nil {
		t.Fatalf("expected parse error for invalid base64 body")
	}
}

func TestEscapeBatchPathSegment(t *testing.T) {
	got := escapeBatchPathSegment("abc/123 x")
	want := "abc%2F123%20x"
	if got != want {
		t.Fatalf("unexpected escaped path segment: got %q want %q", got, want)
	}
}

func TestBatchBuilderEscapesDynamicPathSegments(t *testing.T) {
	builder := (&BatchClient{}).NewBatch().
		Create("c1", "u my/table", map[string]interface{}{"k": "v"}).
		Update("u1", "u my/table", "abc/123", map[string]interface{}{"x": "y"}).
		Delete("d1", "u my/table", "abc/123")

	if len(builder.requests) != 3 {
		t.Fatalf("expected 3 requests, got %d", len(builder.requests))
	}

	if got := builder.requests[0].URL; got != "/api/now/table/u%20my%2Ftable" {
		t.Fatalf("unexpected create URL: %s", got)
	}
	if got := builder.requests[1].URL; got != "/api/now/table/u%20my%2Ftable/abc%2F123" {
		t.Fatalf("unexpected update URL: %s", got)
	}
	if got := builder.requests[2].URL; got != "/api/now/table/u%20my%2Ftable/abc%2F123" {
		t.Fatalf("unexpected delete URL: %s", got)
	}
}
