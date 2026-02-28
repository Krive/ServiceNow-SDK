package identity

import (
	"strings"
	"testing"
)

func TestBuildUserFilterParamsSanitizesValues(t *testing.T) {
	active := true
	filter := &UserFilter{
		Active:     &active,
		Department: "IT^ORactive=false",
		Title:      "Engineer\nSRE",
		Role:       "admin^ORname=guest",
		Group:      "network\rteam",
		OrderBy:    "-sys_created_on",
	}

	params := (&IdentityClient{}).buildUserFilterParams(filter)
	query := params["sysparm_query"]

	expectedFragments := []string{
		"department=IT ORactive=false",
		"titleLIKEEngineer SRE",
		"sys_user_has_role.role.name=admin ORname=guest",
		"sys_user_grmember.group.name=network team",
		"ORDERBYDESCsys_created_on",
	}

	for _, fragment := range expectedFragments {
		if !strings.Contains(query, fragment) {
			t.Fatalf("expected query to contain %q, got %q", fragment, query)
		}
	}
}
