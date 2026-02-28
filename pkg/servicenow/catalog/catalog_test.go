package catalog

import "testing"

func TestSanitizeQueryTerm(t *testing.T) {
	got := sanitizeQueryTerm("network^ORactive=true\nline2")
	want := "network ORactive=true line2"
	if got != want {
		t.Fatalf("unexpected sanitized term: got %q want %q", got, want)
	}
}
