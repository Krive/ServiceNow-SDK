package attachment

import (
	"testing"
)

func TestBuildAttachmentListQueryUsesEncodedSysparmQuery(t *testing.T) {
	gotQuery := buildAttachmentListQuery("incident^ORactive=true", "abc123\nline2")
	want := "table_name=incident ORactive=true^table_sys_id=abc123 line2"
	if gotQuery != want {
		t.Fatalf("unexpected sysparm_query: got=%q want=%q", gotQuery, want)
	}
}

func TestSanitizeEncodedQueryValue(t *testing.T) {
	got := sanitizeEncodedQueryValue("a^ORb\nc\rd")
	want := "a ORb c d"
	if got != want {
		t.Fatalf("unexpected sanitized value: got=%q want=%q", got, want)
	}
}
