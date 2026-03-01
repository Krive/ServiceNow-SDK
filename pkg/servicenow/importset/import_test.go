package importset

import (
	"testing"

	"codeberg.org/Krive/ServiceNow-SDK/pkg/servicenow/core"
)

func TestNormalizeImportRecord(t *testing.T) {
	input := ImportRecord{
		"number":  42,
		"enabled": true,
		"text":    "hello",
		"object":  map[string]interface{}{"k": "v"},
		"empty":   nil,
	}

	got := normalizeImportRecord(input)

	if got["number"] != "42" {
		t.Fatalf("unexpected number conversion: %q", got["number"])
	}
	if got["enabled"] != "true" {
		t.Fatalf("unexpected bool conversion: %q", got["enabled"])
	}
	if got["text"] != "hello" {
		t.Fatalf("unexpected string conversion: %q", got["text"])
	}
	if got["object"] != `{"k":"v"}` {
		t.Fatalf("unexpected object conversion: %q", got["object"])
	}
	if got["empty"] != "" {
		t.Fatalf("unexpected nil conversion: %q", got["empty"])
	}
}

func TestBuildImportSetLookupPathEscapesSysID(t *testing.T) {
	got := buildImportSetLookupPath("abc/123?x=1")
	want := "/table/sys_import_set/abc%2F123%3Fx=1"
	if got != want {
		t.Fatalf("unexpected lookup path: got %q want %q", got, want)
	}
}

func TestBuildImportInsertPathEscapesTableName(t *testing.T) {
	got := buildImportInsertPath("u data/table")
	want := "/import/u%20data%2Ftable"
	if got != want {
		t.Fatalf("unexpected insert path: got %q want %q", got, want)
	}

	gotV1 := buildImportInsertV1Path("u data/table")
	wantV1 := "/v1/import/u%20data%2Ftable"
	if gotV1 != wantV1 {
		t.Fatalf("unexpected v1 insert path: got %q want %q", gotV1, wantV1)
	}
}

func TestShouldRetryWithV1ImportPath(t *testing.T) {
	if shouldRetryWithV1ImportPath(nil) {
		t.Fatalf("nil error should not trigger fallback")
	}

	if !shouldRetryWithV1ImportPath(core.NewServiceNowError(404, "not found")) {
		t.Fatalf("404 should trigger fallback")
	}

	if !shouldRetryWithV1ImportPath(core.NewServiceNowError(405, "method not allowed")) {
		t.Fatalf("405 should trigger fallback")
	}

	if shouldRetryWithV1ImportPath(core.NewServiceNowError(400, "bad request")) {
		t.Fatalf("400 should not trigger fallback")
	}
}

func TestSanitizeEncodedQueryValue(t *testing.T) {
	got := sanitizeEncodedQueryValue("a^ORb\nc\rd")
	want := "a ORb c d"
	if got != want {
		t.Fatalf("unexpected sanitized value: got %q want %q", got, want)
	}
}
