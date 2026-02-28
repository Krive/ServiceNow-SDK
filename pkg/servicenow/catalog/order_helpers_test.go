package catalog

import (
	"reflect"
	"testing"
)

func TestBuildEncodedOrderClauses(t *testing.T) {
	got := buildEncodedOrderClauses("order,title,sys_created_on DESC,-priority,DESC number")
	want := []string{
		"ORDERBYorder",
		"ORDERBYtitle",
		"ORDERBYDESCsys_created_on",
		"ORDERBYDESCpriority",
		"ORDERBYDESCnumber",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected order clauses: got=%v want=%v", got, want)
	}
}

func TestApplyEncodedOrderAppendsToSysparmQuery(t *testing.T) {
	params := map[string]string{
		"sysparm_query": "active=true",
	}

	applyEncodedOrder(params, "order,title")

	if got, want := params["sysparm_query"], "active=true^ORDERBYorder^ORDERBYtitle"; got != want {
		t.Fatalf("unexpected merged query: got=%q want=%q", got, want)
	}
}
