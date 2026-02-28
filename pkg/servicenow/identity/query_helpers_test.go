package identity

import "testing"

func TestBuildEncodedOrderClause(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "empty", input: "", want: ""},
		{name: "asc default", input: "name", want: "ORDERBYname"},
		{name: "dash desc", input: "-sys_created_on", want: "ORDERBYDESCsys_created_on"},
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

func TestSanitizeEncodedQueryValue(t *testing.T) {
	got := sanitizeEncodedQueryValue("a^ORb\nc\rd")
	want := "a ORb c d"
	if got != want {
		t.Fatalf("unexpected sanitized value: got %q want %q", got, want)
	}
}
