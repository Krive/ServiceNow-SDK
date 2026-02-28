package cmdb

import "testing"

func TestExtractReferenceString(t *testing.T) {
	if got := extractReferenceString("cmdb_ci_server"); got != "cmdb_ci_server" {
		t.Fatalf("unexpected direct string value: %s", got)
	}

	if got := extractReferenceString(map[string]interface{}{"value": "cmdb_ci_vm"}); got != "cmdb_ci_vm" {
		t.Fatalf("unexpected reference value extraction: %s", got)
	}

	if got := extractReferenceString(map[string]interface{}{"display_value": "Server"}); got != "Server" {
		t.Fatalf("unexpected display_value fallback: %s", got)
	}

	if got := extractReferenceString(map[string]interface{}{}); got != "" {
		t.Fatalf("expected empty value, got: %s", got)
	}
}

func TestBuildEncodedOrderClause(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "empty", input: "", want: ""},
		{name: "asc default", input: "name", want: "ORDERBYname"},
		{name: "dash desc", input: "-sys_updated_on", want: "ORDERBYDESCsys_updated_on"},
		{name: "desc prefix", input: "DESC priority", want: "ORDERBYDESCpriority"},
		{name: "asc prefix", input: "ASC number", want: "ORDERBYnumber"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildEncodedOrderClause(tt.input)
			if got != tt.want {
				t.Fatalf("unexpected order clause for %q: got %q want %q", tt.input, got, tt.want)
			}
		})
	}
}
