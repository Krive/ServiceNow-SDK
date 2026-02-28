package table

import "testing"

func TestExtractSysID(t *testing.T) {
	if got, err := extractSysID("abc123"); err != nil || got != "abc123" {
		t.Fatalf("unexpected direct sys_id extraction: got=%q err=%v", got, err)
	}

	if got, err := extractSysID(map[string]interface{}{"value": "v123"}); err != nil || got != "v123" {
		t.Fatalf("unexpected value sys_id extraction: got=%q err=%v", got, err)
	}

	if got, err := extractSysID(map[string]interface{}{"sys_id": "s123"}); err != nil || got != "s123" {
		t.Fatalf("unexpected sys_id map extraction: got=%q err=%v", got, err)
	}

	if got, err := extractSysID(map[string]interface{}{"display_value": "d123"}); err != nil || got != "d123" {
		t.Fatalf("unexpected display_value extraction: got=%q err=%v", got, err)
	}

	if _, err := extractSysID(map[string]interface{}{}); err == nil {
		t.Fatalf("expected error for empty sys_id map")
	}
}

func TestParseCountValue(t *testing.T) {
	if got := parseCountValue("42"); got != 42 {
		t.Fatalf("unexpected string count parse: %d", got)
	}
	if got := parseCountValue(7); got != 7 {
		t.Fatalf("unexpected int count parse: %d", got)
	}
	if got := parseCountValue(int64(9)); got != 9 {
		t.Fatalf("unexpected int64 count parse: %d", got)
	}
	if got := parseCountValue(11.0); got != 11 {
		t.Fatalf("unexpected float64 count parse: %d", got)
	}
	if got := parseCountValue(struct{}{}); got != 0 {
		t.Fatalf("unexpected fallback count parse: %d", got)
	}
}
