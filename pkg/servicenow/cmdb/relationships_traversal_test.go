package cmdb

import (
	"context"
	"testing"
)

func TestGetDependencyMapBuildsDependenciesAndDependents(t *testing.T) {
	relClient := &RelationshipClient{
		client: &CMDBClient{},
		resolveCI: func(_ context.Context, sysID string) (*ConfigurationItem, error) {
			return &ConfigurationItem{SysID: sysID, SysClassName: "cmdb_ci_server"}, nil
		},
		resolveParentRelationships: func(_ context.Context, ciSysID string) ([]*CIRelationship, error) {
			if ciSysID == "root" {
				return []*CIRelationship{{SysID: "rel_dep", Parent: "dep", Child: "root"}}, nil
			}
			return nil, nil
		},
		resolveChildRelationships: func(_ context.Context, ciSysID string) ([]*CIRelationship, error) {
			if ciSysID == "root" {
				return []*CIRelationship{{SysID: "rel_child", Parent: "root", Child: "child"}}, nil
			}
			return nil, nil
		},
	}

	depMap, err := relClient.GetDependencyMapWithContext(context.Background(), "root", 1)
	if err != nil {
		t.Fatalf("get dependency map failed: %v", err)
	}

	if len(depMap.Dependencies) != 1 || depMap.Dependencies[0].SysID != "dep" {
		t.Fatalf("unexpected dependencies: %+v", depMap.Dependencies)
	}
	if len(depMap.Dependents) != 1 || depMap.Dependents[0].SysID != "child" {
		t.Fatalf("unexpected dependents: %+v", depMap.Dependents)
	}
}
