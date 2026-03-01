package aggregate

import (
	"testing"

	"codeberg.org/Krive/ServiceNow-SDK/pkg/servicenow/query"
)

func TestBuildParamsUsesDocumentedOrderAndCountParams(t *testing.T) {
	ac := &AggregateClient{tableName: "incident"}

	params := ac.NewQuery().
		CountAll("count").
		Sum("priority", "priority_sum").
		GroupByField("state", "").
		OrderByAsc("state").
		OrderByDesc("sys_created_on").
		BuildParams()

	if got := params["sysparm_count"]; got != "true" {
		t.Fatalf("expected sysparm_count=true, got %q", got)
	}
	if got := params["sysparm_sum_fields"]; got != "priority" {
		t.Fatalf("unexpected sysparm_sum_fields: %q", got)
	}
	if got := params["sysparm_group_by"]; got != "state" {
		t.Fatalf("unexpected sysparm_group_by: %q", got)
	}
	if got := params["sysparm_order_by"]; got != "state" {
		t.Fatalf("unexpected sysparm_order_by: %q", got)
	}
	if got := params["sysparm_order_by_desc"]; got != "sys_created_on" {
		t.Fatalf("unexpected sysparm_order_by_desc: %q", got)
	}

	if _, exists := params["sysparm_orderby"]; exists {
		t.Fatalf("legacy sysparm_orderby should not be set")
	}
	if _, exists := params["sysparm_orderby_desc"]; exists {
		t.Fatalf("legacy sysparm_orderby_desc should not be set")
	}
	if _, exists := params["sysparm_count_fields"]; exists {
		t.Fatalf("unsupported sysparm_count_fields should not be set")
	}
}

func TestBuildParamsCarriesEncodedQuery(t *testing.T) {
	ac := &AggregateClient{tableName: "incident"}
	params := ac.NewQuery().
		Where("active", query.OpEquals, true).
		OrderByAsc("number").
		BuildParams()

	if got := params["sysparm_query"]; got != "active=true" {
		t.Fatalf("unexpected sysparm_query: %q", got)
	}
	if got := params["sysparm_order_by"]; got != "number" {
		t.Fatalf("unexpected sysparm_order_by: %q", got)
	}
}
