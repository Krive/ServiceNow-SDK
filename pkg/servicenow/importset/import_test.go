package importset

import (
	"testing"
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

func TestSanitizeEncodedQueryValue(t *testing.T) {
	got := sanitizeEncodedQueryValue("a^ORb\nc\rd")
	want := "a ORb c d"
	if got != want {
		t.Fatalf("unexpected sanitized value: got %q want %q", got, want)
	}
}
