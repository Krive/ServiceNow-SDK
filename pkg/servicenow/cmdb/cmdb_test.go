package cmdb

import (
	"strings"
	"testing"
	"time"
)

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

func TestBuildFilterParamsIncludesDateFiltersAndSanitizesValues(t *testing.T) {
	client := &CMDBClient{}
	filter := &CIFilter{
		State:         "1^ORactive=true",
		Name:          "db\nserver",
		CreatedAfter:  time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC),
		CreatedBefore: time.Date(2025, 1, 3, 3, 4, 5, 0, time.UTC),
		UpdatedAfter:  time.Date(2025, 1, 4, 3, 4, 5, 0, time.UTC),
		UpdatedBefore: time.Date(2025, 1, 5, 3, 4, 5, 0, time.UTC),
		OrderBy:       "-sys_updated_on",
	}

	params := client.buildFilterParams(filter)
	query := params["sysparm_query"]

	expectedFragments := []string{
		"install_status=1 ORactive=true",
		"nameLIKEdb server",
		"sys_created_on>=2025-01-02 03:04:05",
		"sys_created_on<=2025-01-03 03:04:05",
		"sys_updated_on>=2025-01-04 03:04:05",
		"sys_updated_on<=2025-01-05 03:04:05",
		"ORDERBYDESCsys_updated_on",
	}

	for _, fragment := range expectedFragments {
		if !strings.Contains(query, fragment) {
			t.Fatalf("expected query to contain %q, got %q", fragment, query)
		}
	}

	if strings.Contains(query, "install_status=1^ORactive=true") {
		t.Fatalf("query value should be sanitized, got %q", query)
	}
}
