package cmdb

import (
	"context"
	"fmt"
	"time"

	"github.com/Krive/ServiceNow-SDK/pkg/servicenow/core"
)

// RelationshipClient handles CI relationship operations
type RelationshipClient struct {
	client *CMDBClient
}

// NewRelationshipClient creates a new relationship client
func (c *CMDBClient) NewRelationshipClient() *RelationshipClient {
	return &RelationshipClient{client: c}
}

// GetRelationships retrieves all relationships for a CI
func (r *RelationshipClient) GetRelationships(ciSysID string) ([]*CIRelationship, error) {
	return r.GetRelationshipsWithContext(context.Background(), ciSysID)
}

// GetRelationshipsWithContext retrieves all relationships for a CI with context support
func (r *RelationshipClient) GetRelationshipsWithContext(ctx context.Context, ciSysID string) ([]*CIRelationship, error) {
	params := map[string]string{
		"sysparm_query": fmt.Sprintf("parent=%s^ORchild=%s", ciSysID, ciSysID),
	}

	var result core.Response
	err := r.client.client.RawRequestWithContext(ctx, "GET", "/table/cmdb_rel_ci", nil, params, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to get relationships: %w", err)
	}

	results, ok := result.Result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for relationships: %T", result.Result)
	}

	var relationships []*CIRelationship
	for _, result := range results {
		relData, ok := result.(map[string]interface{})
		if !ok {
			continue
		}
		relationships = append(relationships, r.mapDataToRelationship(relData))
	}

	return relationships, nil
}

// GetParentRelationships retrieves relationships where the CI is a child
func (r *RelationshipClient) GetParentRelationships(ciSysID string) ([]*CIRelationship, error) {
	return r.GetParentRelationshipsWithContext(context.Background(), ciSysID)
}

// GetParentRelationshipsWithContext retrieves parent relationships with context support
func (r *RelationshipClient) GetParentRelationshipsWithContext(ctx context.Context, ciSysID string) ([]*CIRelationship, error) {
	params := map[string]string{
		"sysparm_query": fmt.Sprintf("child=%s", ciSysID),
	}

	var result core.Response
	err := r.client.client.RawRequestWithContext(ctx, "GET", "/table/cmdb_rel_ci", nil, params, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to get parent relationships: %w", err)
	}

	results, ok := result.Result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for parent relationships: %T", result.Result)
	}

	var relationships []*CIRelationship
	for _, result := range results {
		relData, ok := result.(map[string]interface{})
		if !ok {
			continue
		}
		relationships = append(relationships, r.mapDataToRelationship(relData))
	}

	return relationships, nil
}

// GetChildRelationships retrieves relationships where the CI is a parent
func (r *RelationshipClient) GetChildRelationships(ciSysID string) ([]*CIRelationship, error) {
	return r.GetChildRelationshipsWithContext(context.Background(), ciSysID)
}

// GetChildRelationshipsWithContext retrieves child relationships with context support
func (r *RelationshipClient) GetChildRelationshipsWithContext(ctx context.Context, ciSysID string) ([]*CIRelationship, error) {
	params := map[string]string{
		"sysparm_query": fmt.Sprintf("parent=%s", ciSysID),
	}

	var result core.Response
	err := r.client.client.RawRequestWithContext(ctx, "GET", "/table/cmdb_rel_ci", nil, params, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to get child relationships: %w", err)
	}

	results, ok := result.Result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for child relationships: %T", result.Result)
	}

	var relationships []*CIRelationship
	for _, result := range results {
		relData, ok := result.(map[string]interface{})
		if !ok {
			continue
		}
		relationships = append(relationships, r.mapDataToRelationship(relData))
	}

	return relationships, nil
}

// CreateRelationship creates a new relationship between CIs
func (r *RelationshipClient) CreateRelationship(parentSysID, childSysID, relType string) (*CIRelationship, error) {
	return r.CreateRelationshipWithContext(context.Background(), parentSysID, childSysID, relType)
}

// CreateRelationshipWithContext creates a new relationship with context support
func (r *RelationshipClient) CreateRelationshipWithContext(ctx context.Context, parentSysID, childSysID, relType string) (*CIRelationship, error) {
	relationshipData := map[string]interface{}{
		"parent": parentSysID,
		"child":  childSysID,
		"type":   relType,
	}

	var result core.Response
	err := r.client.client.RawRequestWithContext(ctx, "POST", "/table/cmdb_rel_ci", relationshipData, nil, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to create relationship: %w", err)
	}

	resultData, ok := result.Result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for relationship creation: %T", result.Result)
	}

	return r.mapDataToRelationship(resultData), nil
}

// DeleteRelationship removes a relationship
func (r *RelationshipClient) DeleteRelationship(relationshipSysID string) error {
	return r.DeleteRelationshipWithContext(context.Background(), relationshipSysID)
}

// DeleteRelationshipWithContext removes a relationship with context support
func (r *RelationshipClient) DeleteRelationshipWithContext(ctx context.Context, relationshipSysID string) error {
	err := r.client.client.RawRequestWithContext(ctx, "DELETE", fmt.Sprintf("/table/cmdb_rel_ci/%s", relationshipSysID), nil, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to delete relationship: %w", err)
	}
	return nil
}

// GetDependencyMap builds a dependency map for a CI showing its dependencies and dependents
func (r *RelationshipClient) GetDependencyMap(ciSysID string, depth int) (*CIDependencyMap, error) {
	return r.GetDependencyMapWithContext(context.Background(), ciSysID, depth)
}

// GetDependencyMapWithContext builds a dependency map with context support
func (r *RelationshipClient) GetDependencyMapWithContext(ctx context.Context, ciSysID string, depth int) (*CIDependencyMap, error) {
	// Get the root CI
	rootCI, err := r.client.GetCIWithContext(ctx, ciSysID)
	if err != nil {
		return nil, fmt.Errorf("failed to get root CI: %w", err)
	}

	depMap := &CIDependencyMap{
		RootCI:        rootCI,
		Dependencies:  []*ConfigurationItem{},
		Dependents:    []*ConfigurationItem{},
		Relationships: []*CIRelationship{},
		Depth:         depth,
	}

	visited := make(map[string]bool)

	// Build dependency tree recursively
	err = r.buildDependencyTree(ctx, ciSysID, depMap, visited, depth, true)
	if err != nil {
		return nil, fmt.Errorf("failed to build dependency tree: %w", err)
	}

	// Build dependent tree recursively
	err = r.buildDependencyTree(ctx, ciSysID, depMap, visited, depth, false)
	if err != nil {
		return nil, fmt.Errorf("failed to build dependent tree: %w", err)
	}

	return depMap, nil
}

// buildDependencyTree recursively builds the dependency tree
func (r *RelationshipClient) buildDependencyTree(ctx context.Context, ciSysID string, depMap *CIDependencyMap, visited map[string]bool, depth int, getDependencies bool) error {
	if depth <= 0 || visited[ciSysID] {
		return nil
	}

	visited[ciSysID] = true

	var relationships []*CIRelationship
	var err error

	if getDependencies {
		// Get what this CI depends on (parent relationships)
		relationships, err = r.GetParentRelationshipsWithContext(ctx, ciSysID)
	} else {
		// Get what depends on this CI (child relationships)
		relationships, err = r.GetChildRelationshipsWithContext(ctx, ciSysID)
	}

	if err != nil {
		return err
	}

	for _, rel := range relationships {
		depMap.Relationships = append(depMap.Relationships, rel)

		var relatedCISysID string
		if getDependencies {
			relatedCISysID = rel.Parent
		} else {
			relatedCISysID = rel.Child
		}

		// Get the related CI
		relatedCI, err := r.client.GetCIWithContext(ctx, relatedCISysID)
		if err != nil {
			continue // Skip if we can't get the CI
		}

		// Add to appropriate list
		if getDependencies {
			depMap.Dependencies = append(depMap.Dependencies, relatedCI)
		} else {
			depMap.Dependents = append(depMap.Dependents, relatedCI)
		}

		// Recurse for deeper levels
		err = r.buildDependencyTree(ctx, relatedCISysID, depMap, visited, depth-1, getDependencies)
		if err != nil {
			continue // Continue with other relationships if one fails
		}
	}

	return nil
}

// GetRelationshipsByType retrieves relationships of a specific type
func (r *RelationshipClient) GetRelationshipsByType(relType string) ([]*CIRelationship, error) {
	return r.GetRelationshipsByTypeWithContext(context.Background(), relType)
}

// GetRelationshipsByTypeWithContext retrieves relationships by type with context support
func (r *RelationshipClient) GetRelationshipsByTypeWithContext(ctx context.Context, relType string) ([]*CIRelationship, error) {
	params := map[string]string{
		"sysparm_query": fmt.Sprintf("type=%s", relType),
	}

	var result core.Response
	err := r.client.client.RawRequestWithContext(ctx, "GET", "/table/cmdb_rel_ci", nil, params, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to get relationships by type: %w", err)
	}

	results, ok := result.Result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for relationships by type: %T", result.Result)
	}

	var relationships []*CIRelationship
	for _, result := range results {
		relData, ok := result.(map[string]interface{})
		if !ok {
			continue
		}
		relationships = append(relationships, r.mapDataToRelationship(relData))
	}

	return relationships, nil
}

// GetRelationshipTypes retrieves all available relationship types
func (r *RelationshipClient) GetRelationshipTypes() ([]string, error) {
	return r.GetRelationshipTypesWithContext(context.Background())
}

// GetRelationshipTypesWithContext retrieves relationship types with context support
func (r *RelationshipClient) GetRelationshipTypesWithContext(ctx context.Context) ([]string, error) {
	params := map[string]string{
		"sysparm_fields": "type",
		"sysparm_query":  "type!=NULL",
	}

	var result core.Response
	err := r.client.client.RawRequestWithContext(ctx, "GET", "/table/cmdb_rel_type", nil, params, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to get relationship types: %w", err)
	}

	results, ok := result.Result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for relationship types: %T", result.Result)
	}

	var types []string
	typeSet := make(map[string]bool)

	for _, result := range results {
		typeData, ok := result.(map[string]interface{})
		if !ok {
			continue
		}
		if relType, ok := typeData["type"].(string); ok && relType != "" {
			if !typeSet[relType] {
				types = append(types, relType)
				typeSet[relType] = true
			}
		}
	}

	return types, nil
}

// FindPath finds a path between two CIs through relationships
func (r *RelationshipClient) FindPath(fromCISysID, toCISysID string, maxDepth int) ([][]*CIRelationship, error) {
	return r.FindPathWithContext(context.Background(), fromCISysID, toCISysID, maxDepth)
}

// FindPathWithContext finds paths between CIs with context support
func (r *RelationshipClient) FindPathWithContext(ctx context.Context, fromCISysID, toCISysID string, maxDepth int) ([][]*CIRelationship, error) {
	var paths [][]*CIRelationship
	visited := make(map[string]bool)
	currentPath := []*CIRelationship{}

	err := r.findPathRecursive(ctx, fromCISysID, toCISysID, maxDepth, visited, currentPath, &paths)
	if err != nil {
		return nil, err
	}

	return paths, nil
}

// findPathRecursive recursively finds paths between CIs
func (r *RelationshipClient) findPathRecursive(ctx context.Context, currentCI, targetCI string, depth int, visited map[string]bool, currentPath []*CIRelationship, paths *[][]*CIRelationship) error {
	if depth <= 0 || visited[currentCI] {
		return nil
	}

	if currentCI == targetCI && len(currentPath) > 0 {
		// Found a path, add it to results
		pathCopy := make([]*CIRelationship, len(currentPath))
		copy(pathCopy, currentPath)
		*paths = append(*paths, pathCopy)
		return nil
	}

	visited[currentCI] = true

	// Get all relationships from current CI
	relationships, err := r.GetRelationshipsWithContext(ctx, currentCI)
	if err != nil {
		visited[currentCI] = false
		return err
	}

	for _, rel := range relationships {
		var nextCI string
		if rel.Parent == currentCI {
			nextCI = rel.Child
		} else {
			nextCI = rel.Parent
		}

		if !visited[nextCI] {
			newPath := append(currentPath, rel)
			err := r.findPathRecursive(ctx, nextCI, targetCI, depth-1, visited, newPath, paths)
			if err != nil {
				continue // Continue with other relationships
			}
		}
	}

	visited[currentCI] = false
	return nil
}

// GetImpactAnalysis analyzes the impact of a CI change or outage
func (r *RelationshipClient) GetImpactAnalysis(ciSysID string, depth int) (*CIDependencyMap, error) {
	return r.GetImpactAnalysisWithContext(context.Background(), ciSysID, depth)
}

// GetImpactAnalysisWithContext analyzes impact with context support
func (r *RelationshipClient) GetImpactAnalysisWithContext(ctx context.Context, ciSysID string, depth int) (*CIDependencyMap, error) {
	// Impact analysis focuses on what depends on this CI (dependents)
	depMap, err := r.GetDependencyMapWithContext(ctx, ciSysID, depth)
	if err != nil {
		return nil, err
	}

	// Filter to only include impacted CIs (dependents)
	impactMap := &CIDependencyMap{
		RootCI:        depMap.RootCI,
		Dependencies:  []*ConfigurationItem{}, // Empty for impact analysis
		Dependents:    depMap.Dependents,
		Relationships: []*CIRelationship{},
		Depth:         depth,
	}

	// Only include relationships where the root CI or its dependents are parents
	for _, rel := range depMap.Relationships {
		if rel.Parent == ciSysID {
			impactMap.Relationships = append(impactMap.Relationships, rel)
		} else {
			// Check if the parent is in our dependents list
			for _, dependent := range depMap.Dependents {
				if rel.Parent == dependent.SysID {
					impactMap.Relationships = append(impactMap.Relationships, rel)
					break
				}
			}
		}
	}

	return impactMap, nil
}

// BulkCreateRelationships creates multiple relationships in one operation
func (r *RelationshipClient) BulkCreateRelationships(relationships []map[string]interface{}) ([]*CIRelationship, error) {
	return r.BulkCreateRelationshipsWithContext(context.Background(), relationships)
}

// BulkCreateRelationshipsWithContext creates multiple relationships with context support
func (r *RelationshipClient) BulkCreateRelationshipsWithContext(ctx context.Context, relationships []map[string]interface{}) ([]*CIRelationship, error) {
	var createdRelationships []*CIRelationship

	for _, relData := range relationships {
		var result core.Response
		err := r.client.client.RawRequestWithContext(ctx, "POST", "/table/cmdb_rel_ci", relData, nil, &result)
		if err != nil {
			return createdRelationships, fmt.Errorf("failed to create relationship: %w", err)
		}

		resultData, ok := result.Result.(map[string]interface{})
		if !ok {
			continue
		}

		createdRelationships = append(createdRelationships, r.mapDataToRelationship(resultData))
	}

	return createdRelationships, nil
}

// Helper method to map raw data to CIRelationship struct
func (r *RelationshipClient) mapDataToRelationship(data map[string]interface{}) *CIRelationship {
	rel := &CIRelationship{
		Attributes: make(map[string]interface{}),
	}

	if sysID, ok := data["sys_id"].(string); ok {
		rel.SysID = sysID
	}
	if parent, ok := data["parent"].(string); ok {
		rel.Parent = parent
	}
	if child, ok := data["child"].(string); ok {
		rel.Child = child
	}
	if relType, ok := data["type"].(string); ok {
		rel.Type = relType
	}
	if connectionType, ok := data["connection_type"].(string); ok {
		rel.ConnectionType = connectionType
	}
	if parentDescriptor, ok := data["parent_descriptor"].(string); ok {
		rel.ParentDescriptor = parentDescriptor
	}
	if childDescriptor, ok := data["child_descriptor"].(string); ok {
		rel.ChildDescriptor = childDescriptor
	}
	if direction, ok := data["direction"].(string); ok {
		rel.Direction = direction
	}
	if weight, ok := data["weight"].(string); ok {
		if w, err := fmt.Sscanf(weight, "%d", &rel.Weight); err == nil && w == 1 {
			// Successfully parsed
		}
	}
	if createdBy, ok := data["sys_created_by"].(string); ok {
		rel.CreatedBy = createdBy
	}
	if updatedBy, ok := data["sys_updated_by"].(string); ok {
		rel.UpdatedBy = updatedBy
	}

	// Parse timestamps
	if createdOn, ok := data["sys_created_on"].(string); ok {
		if t, err := time.Parse("2006-01-02 15:04:05", createdOn); err == nil {
			rel.CreatedOn = t
		}
	}
	if updatedOn, ok := data["sys_updated_on"].(string); ok {
		if t, err := time.Parse("2006-01-02 15:04:05", updatedOn); err == nil {
			rel.UpdatedOn = t
		}
	}

	// Store any additional attributes
	standardFields := map[string]bool{
		"sys_id": true, "parent": true, "child": true, "type": true,
		"connection_type": true, "parent_descriptor": true, "child_descriptor": true,
		"direction": true, "weight": true, "sys_created_by": true, "sys_updated_by": true,
		"sys_created_on": true, "sys_updated_on": true,
	}

	for key, value := range data {
		if !standardFields[key] {
			rel.Attributes[key] = value
		}
	}

	return rel
}
