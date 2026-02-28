package query

import "testing"

func TestBuildEncodesAscendingAndDescendingOrderInQuery(t *testing.T) {
	params := New().
		OrderByAsc("sys_updated_on").
		OrderByDesc("priority").
		Build()

	if got := params["sysparm_query"]; got != "ORDERBYsys_updated_on^ORDERBYDESCpriority" {
		t.Fatalf("unexpected encoded order query: got %q", got)
	}
	if _, ok := params["sysparm_orderby"]; ok {
		t.Fatalf("sysparm_orderby should not be set")
	}
	if _, ok := params["sysparm_orderby_desc"]; ok {
		t.Fatalf("sysparm_orderby_desc should not be set")
	}
}

func TestBuildDoesNotPreEscapeQueryValues(t *testing.T) {
	params := New().Equals("short_description", "CPU outage + network").Build()
	want := "short_description=CPU outage + network"
	if got := params["sysparm_query"]; got != want {
		t.Fatalf("unexpected query: got %q want %q", got, want)
	}
}

func TestBuildSanitizesEncodedQueryControlCharacters(t *testing.T) {
	params := New().Equals("short_description", "a^ORactive=true\nline2").Build()
	want := "short_description=a ORactive=true line2"
	if got := params["sysparm_query"]; got != want {
		t.Fatalf("unexpected sanitized query: got %q want %q", got, want)
	}
}
