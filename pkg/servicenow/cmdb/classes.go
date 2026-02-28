package cmdb

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Krive/ServiceNow-SDK/pkg/servicenow/core"
)

// ClassClient handles CI class operations
type ClassClient struct {
	client *CMDBClient
}

// NewClassClient creates a new class client
func (c *CMDBClient) NewClassClient() *ClassClient {
	return &ClassClient{client: c}
}

// GetCIClass retrieves a CI class definition
func (c *ClassClient) GetCIClass(className string) (*CIClass, error) {
	return c.GetCIClassWithContext(context.Background(), className)
}

// GetCIClassWithContext retrieves a CI class definition with context support
func (c *ClassClient) GetCIClassWithContext(ctx context.Context, className string) (*CIClass, error) {
	params := map[string]string{
		"sysparm_query": fmt.Sprintf("name=%s", sanitizeEncodedQueryValue(className)),
		"sysparm_limit": "1",
	}

	var result core.Response
	err := c.client.client.RawRequestWithContext(ctx, "GET", "/table/sys_db_object", nil, params, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to get CI class: %w", err)
	}

	results, ok := result.Result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for CI class: %T", result.Result)
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("CI class not found: %s", className)
	}

	classData, ok := results[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected class data type: %T", results[0])
	}

	return c.mapDataToCIClass(classData), nil
}

// ListCIClasses retrieves all CI classes
func (c *ClassClient) ListCIClasses() ([]*CIClass, error) {
	return c.ListCIClassesWithContext(context.Background())
}

// ListCIClassesWithContext retrieves all CI classes with context support
func (c *ClassClient) ListCIClassesWithContext(ctx context.Context) ([]*CIClass, error) {
	params := map[string]string{
		"sysparm_query": "super_class.name=cmdb_ci^ORname=cmdb_ci",
	}

	var result core.Response
	err := c.client.client.RawRequestWithContext(ctx, "GET", "/table/sys_db_object", nil, params, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to list CI classes: %w", err)
	}

	results, ok := result.Result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for CI classes: %T", result.Result)
	}

	var classes []*CIClass
	for _, r := range results {
		classData, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		classes = append(classes, c.mapDataToCIClass(classData))
	}

	return classes, nil
}

// GetClassHierarchy retrieves the class hierarchy starting from a root class
func (c *ClassClient) GetClassHierarchy(rootClass string) (map[string][]*CIClass, error) {
	return c.GetClassHierarchyWithContext(context.Background(), rootClass)
}

// GetClassHierarchyWithContext retrieves class hierarchy with context support
func (c *ClassClient) GetClassHierarchyWithContext(ctx context.Context, rootClass string) (map[string][]*CIClass, error) {
	hierarchy := make(map[string][]*CIClass)
	visited := make(map[string]bool)

	err := c.buildClassHierarchy(ctx, rootClass, hierarchy, visited)
	if err != nil {
		return nil, err
	}

	return hierarchy, nil
}

// buildClassHierarchy recursively builds the class hierarchy
func (c *ClassClient) buildClassHierarchy(ctx context.Context, className string, hierarchy map[string][]*CIClass, visited map[string]bool) error {
	if visited[className] {
		return nil
	}
	visited[className] = true

	// Get child classes
	params := map[string]string{
		"sysparm_query": fmt.Sprintf("super_class.name=%s", sanitizeEncodedQueryValue(className)),
	}

	var result core.Response
	err := c.client.client.RawRequestWithContext(ctx, "GET", "/table/sys_db_object", nil, params, &result)
	if err != nil {
		return fmt.Errorf("failed to get child classes for %s: %w", className, err)
	}

	results, ok := result.Result.([]interface{})
	if !ok {
		return fmt.Errorf("unexpected result type for child classes: %T", result.Result)
	}

	var childClasses []*CIClass
	for _, r := range results {
		classData, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		childClass := c.mapDataToCIClass(classData)
		childClasses = append(childClasses, childClass)

		// Recursively get children of this child
		err := c.buildClassHierarchy(ctx, childClass.Name, hierarchy, visited)
		if err != nil {
			continue // Continue with other classes if one fails
		}
	}

	hierarchy[className] = childClasses
	return nil
}

// GetParentClass retrieves the parent class of a CI class
func (c *ClassClient) GetParentClass(className string) (*CIClass, error) {
	return c.GetParentClassWithContext(context.Background(), className)
}

// GetParentClassWithContext retrieves parent class with context support
func (c *ClassClient) GetParentClassWithContext(ctx context.Context, className string) (*CIClass, error) {
	class, err := c.GetCIClassWithContext(ctx, className)
	if err != nil {
		return nil, err
	}

	if class.SuperClass == "" {
		return nil, fmt.Errorf("class %s has no parent class", className)
	}

	return c.GetCIClassWithContext(ctx, class.SuperClass)
}

// GetClassAttributes retrieves attributes for a CI class
func (c *ClassClient) GetClassAttributes(className string) ([]string, error) {
	return c.GetClassAttributesWithContext(context.Background(), className)
}

// GetClassAttributesWithContext retrieves class attributes with context support
func (c *ClassClient) GetClassAttributesWithContext(ctx context.Context, className string) ([]string, error) {
	params := map[string]string{
		"sysparm_query":  fmt.Sprintf("name=%s", sanitizeEncodedQueryValue(className)),
		"sysparm_fields": "column_label,element",
	}

	var result core.Response
	err := c.client.client.RawRequestWithContext(ctx, "GET", "/table/sys_dictionary", nil, params, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to get class attributes: %w", err)
	}

	results, ok := result.Result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for class attributes: %T", result.Result)
	}

	var attributes []string
	for _, r := range results {
		attrData, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		if element, ok := attrData["element"].(string); ok && element != "" {
			attributes = append(attributes, element)
		}
	}

	return attributes, nil
}

// IsSubclassOf checks if a class is a subclass of another class
func (c *ClassClient) IsSubclassOf(childClass, parentClass string) (bool, error) {
	return c.IsSubclassOfWithContext(context.Background(), childClass, parentClass)
}

// IsSubclassOfWithContext checks inheritance relationship with context support
func (c *ClassClient) IsSubclassOfWithContext(ctx context.Context, childClass, parentClass string) (bool, error) {
	if childClass == parentClass {
		return true, nil
	}

	currentClass := childClass
	visited := make(map[string]bool)

	for currentClass != "" && !visited[currentClass] {
		visited[currentClass] = true

		class, err := c.GetCIClassWithContext(ctx, currentClass)
		if err != nil {
			return false, err
		}

		if class.SuperClass == parentClass {
			return true, nil
		}

		currentClass = class.SuperClass
	}

	return false, nil
}

// Helper method to map raw data to CIClass struct
func (c *ClassClient) mapDataToCIClass(data map[string]interface{}) *CIClass {
	class := &CIClass{}

	if sysID, ok := data["sys_id"].(string); ok {
		class.SysID = sysID
	}
	if name, ok := data["name"].(string); ok {
		class.Name = name
		class.TableName = name
	}
	if label, ok := data["label"].(string); ok {
		class.Label = label
	}
	if superClass, ok := data["super_class"].(string); ok {
		class.SuperClass = superClass
	}
	if pkg, ok := data["sys_package"].(string); ok {
		class.Package = pkg
	}
	if active, ok := data["active"].(string); ok {
		class.Active = active == "true"
	}
	if abstract, ok := data["abstract"].(string); ok {
		class.Abstract = abstract == "true"
	}
	if extensible, ok := data["extensible"].(string); ok {
		class.Extensible = extensible == "true"
	}
	if numberPrefix, ok := data["number_ref"].(string); ok {
		class.NumberPrefix = numberPrefix
	}
	if description, ok := data["sys_documentation"].(string); ok {
		class.Description = description
	}
	if createdBy, ok := data["sys_created_by"].(string); ok {
		class.CreatedBy = createdBy
	}
	if updatedBy, ok := data["sys_updated_by"].(string); ok {
		class.UpdatedBy = updatedBy
	}

	// Parse timestamps
	if createdOn, ok := data["sys_created_on"].(string); ok {
		if t, err := time.Parse("2006-01-02 15:04:05", createdOn); err == nil {
			class.CreatedOn = t
		}
	}
	if updatedOn, ok := data["sys_updated_on"].(string); ok {
		if t, err := time.Parse("2006-01-02 15:04:05", updatedOn); err == nil {
			class.UpdatedOn = t
		}
	}

	return class
}

// IdentificationClient handles CI identification operations
type IdentificationClient struct {
	client *CMDBClient
}

// NewIdentificationClient creates a new identification client
func (c *CMDBClient) NewIdentificationClient() *IdentificationClient {
	return &IdentificationClient{client: c}
}

// IdentifyCIs identifies existing CIs based on provided data
func (i *IdentificationClient) IdentifyCIs(request *CIIdentificationRequest) (*CIIdentificationResult, error) {
	return i.IdentifyCIsWithContext(context.Background(), request)
}

// IdentifyCIsWithContext identifies CIs with context support
func (i *IdentificationClient) IdentifyCIsWithContext(ctx context.Context, request *CIIdentificationRequest) (*CIIdentificationResult, error) {
	result := &CIIdentificationResult{
		Matches:   []CIMatch{},
		NoMatches: []map[string]interface{}{},
	}

	for _, item := range request.Items {
		matches, err := i.identifyItem(ctx, item, request.Options)
		if err != nil {
			// Add to no matches if identification fails
			result.NoMatches = append(result.NoMatches, item)
			continue
		}

		if len(matches) > 0 {
			result.Matches = append(result.Matches, matches...)
		} else {
			result.NoMatches = append(result.NoMatches, item)
		}
	}

	return result, nil
}

// identifyItem identifies a single CI item
func (i *IdentificationClient) identifyItem(ctx context.Context, item map[string]interface{}, options *IdentificationOptions) ([]CIMatch, error) {
	var matches []CIMatch

	if options == nil {
		options = &IdentificationOptions{
			MatchingAttributes: []string{"name", "serial_number", "asset_tag", "ip_address", "fqdn"},
			Threshold:          0.8,
			Strategy:           "exact_match",
		}
	}

	className := "cmdb_ci"
	if options.ClassName != "" {
		className = sanitizeEncodedQueryValue(options.ClassName)
	}

	// Build query based on matching attributes
	var queryParts []string
	for _, attr := range options.MatchingAttributes {
		if value, exists := item[attr]; exists && value != "" {
			sanitizedAttr := sanitizeEncodedQueryValue(attr)
			sanitizedValue := sanitizeEncodedQueryValue(fmt.Sprintf("%v", value))
			if sanitizedAttr == "" || sanitizedValue == "" {
				continue
			}

			switch options.Strategy {
			case "exact_match":
				queryParts = append(queryParts, fmt.Sprintf("%s=%s", sanitizedAttr, sanitizedValue))
			case "fuzzy_match":
				queryParts = append(queryParts, fmt.Sprintf("%sLIKE%s", sanitizedAttr, sanitizedValue))
			}
		}
	}

	if len(queryParts) == 0 {
		return matches, nil
	}

	// Execute search
	params := map[string]string{
		"sysparm_query": strings.Join(queryParts, "^OR"),
		"sysparm_limit": "10", // Limit to top 10 matches
	}

	var result core.Response
	err := i.client.client.RawRequestWithContext(ctx, "GET", buildCMDBTablePath(className), nil, params, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to search for CI matches: %w", err)
	}

	results, ok := result.Result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for CI search: %T", result.Result)
	}

	// Process matches and calculate scores
	for _, r := range results {
		ciData, ok := r.(map[string]interface{})
		if !ok {
			continue
		}

		ci := i.client.mapDataToCI(ciData)
		score, matchedOn := i.calculateMatchScore(item, ciData, options.MatchingAttributes)

		if score >= options.Threshold {
			match := CIMatch{
				InputItem: item,
				MatchedCI: ci,
				Score:     score,
				MatchedOn: matchedOn,
			}
			matches = append(matches, match)
		}
	}

	return matches, nil
}

// calculateMatchScore calculates match score between input item and existing CI
func (i *IdentificationClient) calculateMatchScore(inputItem map[string]interface{}, ciData map[string]interface{}, matchingAttributes []string) (float64, []string) {
	var totalWeight float64
	var matchedWeight float64
	var matchedOn []string

	for _, attr := range matchingAttributes {
		weight := 1.0

		// Give higher weight to unique identifiers
		switch attr {
		case "serial_number", "asset_tag":
			weight = 3.0
		case "ip_address", "fqdn":
			weight = 2.0
		case "name":
			weight = 1.5
		}

		totalWeight += weight

		inputValue, inputExists := inputItem[attr]
		ciValue, ciExists := ciData[attr]

		if inputExists && ciExists && inputValue != "" && ciValue != "" {
			inputStr := fmt.Sprintf("%v", inputValue)
			ciStr := fmt.Sprintf("%v", ciValue)

			if strings.EqualFold(inputStr, ciStr) {
				matchedWeight += weight
				matchedOn = append(matchedOn, attr)
			}
		}
	}

	if totalWeight == 0 {
		return 0, matchedOn
	}

	return matchedWeight / totalWeight, matchedOn
}

// ReconciliationClient handles CI reconciliation operations
type ReconciliationClient struct {
	client *CMDBClient
}

// NewReconciliationClient creates a new reconciliation client
func (c *CMDBClient) NewReconciliationClient() *ReconciliationClient {
	return &ReconciliationClient{client: c}
}

// ReconcileCIs reconciles CI data with existing records
func (r *ReconciliationClient) ReconcileCIs(request *CIReconciliationRequest) (*CIReconciliationResult, error) {
	return r.ReconcileCIsWithContext(context.Background(), request)
}

// ReconcileCIsWithContext reconciles CIs with context support
func (r *ReconciliationClient) ReconcileCIsWithContext(ctx context.Context, request *CIReconciliationRequest) (*CIReconciliationResult, error) {
	result := &CIReconciliationResult{
		Created:      []*ConfigurationItem{},
		Updated:      []*ConfigurationItem{},
		Skipped:      []string{},
		Errors:       []ReconciliationError{},
		TotalItems:   len(request.Items),
		SuccessCount: 0,
		ErrorCount:   0,
		SkippedCount: 0,
	}

	if request.Options == nil {
		request.Options = &ReconciliationOptions{
			CreateMissing:      true,
			UpdateExisting:     true,
			MatchingRules:      []string{"serial_number", "asset_tag", "name"},
			ConflictResolution: "merge",
			DryRun:             false,
			ClassName:          "cmdb_ci",
		}
	}

	// First identify existing CIs
	identificationClient := r.client.NewIdentificationClient()
	identificationRequest := &CIIdentificationRequest{
		Items: request.Items,
		Options: &IdentificationOptions{
			MatchingAttributes: request.Options.MatchingRules,
			Threshold:          0.9,
			Strategy:           "exact_match",
			ClassName:          request.Options.ClassName,
		},
	}

	identificationResult, err := identificationClient.IdentifyCIsWithContext(ctx, identificationRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to identify existing CIs: %w", err)
	}

	// Process matches (update existing CIs)
	for _, match := range identificationResult.Matches {
		if !request.Options.UpdateExisting {
			result.Skipped = append(result.Skipped, match.MatchedCI.SysID)
			result.SkippedCount++
			continue
		}

		if request.Options.DryRun {
			result.Updated = append(result.Updated, match.MatchedCI)
			result.SuccessCount++
			continue
		}

		// Merge input data with existing CI
		updates := r.mergeData(match.InputItem, r.ciToMap(match.MatchedCI), request.Options.ConflictResolution)

		updatedCI, err := r.client.UpdateCIWithContext(ctx, match.MatchedCI.SysClassName, match.MatchedCI.SysID, updates)
		if err != nil {
			result.Errors = append(result.Errors, ReconciliationError{
				Item:    match.InputItem,
				Error:   err.Error(),
				Code:    "UPDATE_FAILED",
				Details: fmt.Sprintf("Failed to update CI %s", match.MatchedCI.SysID),
			})
			result.ErrorCount++
			continue
		}

		result.Updated = append(result.Updated, updatedCI)
		result.SuccessCount++
	}

	// Process no matches (create new CIs)
	for _, item := range identificationResult.NoMatches {
		if !request.Options.CreateMissing {
			itemKey := r.getItemKey(item)
			result.Skipped = append(result.Skipped, itemKey)
			result.SkippedCount++
			continue
		}

		if request.Options.DryRun {
			// Create a dummy CI for dry run
			dummyCI := r.client.mapDataToCI(item)
			result.Created = append(result.Created, dummyCI)
			result.SuccessCount++
			continue
		}

		newCI, err := r.client.CreateCIWithContext(ctx, request.Options.ClassName, item)
		if err != nil {
			result.Errors = append(result.Errors, ReconciliationError{
				Item:    item,
				Error:   err.Error(),
				Code:    "CREATE_FAILED",
				Details: "Failed to create new CI",
			})
			result.ErrorCount++
			continue
		}

		result.Created = append(result.Created, newCI)
		result.SuccessCount++
	}

	return result, nil
}

// mergeData merges input data with existing CI data based on conflict resolution strategy
func (r *ReconciliationClient) mergeData(inputData map[string]interface{}, existingData map[string]interface{}, strategy string) map[string]interface{} {
	merged := make(map[string]interface{})

	switch strategy {
	case "merge":
		// Start with existing data
		for k, v := range existingData {
			merged[k] = v
		}
		// Override with input data (input takes precedence)
		for k, v := range inputData {
			if v != nil && v != "" {
				merged[k] = v
			}
		}
	case "input_wins":
		// Input data completely replaces existing
		for k, v := range inputData {
			merged[k] = v
		}
	case "existing_wins":
		// Keep existing data, only add new fields from input
		for k, v := range existingData {
			merged[k] = v
		}
		for k, v := range inputData {
			if _, exists := merged[k]; !exists {
				merged[k] = v
			}
		}
	}

	return merged
}

// ciToMap converts a ConfigurationItem to a map
func (r *ReconciliationClient) ciToMap(ci *ConfigurationItem) map[string]interface{} {
	data := make(map[string]interface{})

	data["sys_id"] = ci.SysID
	data["name"] = ci.Name
	data["sys_class_name"] = ci.SysClassName
	data["install_status"] = ci.State
	data["operational_status"] = ci.OperationalStatus
	data["category"] = ci.Category
	data["subcategory"] = ci.Subcategory
	data["environment"] = ci.Environment
	data["location"] = ci.Location
	data["owned_by"] = ci.Owner
	data["support_group"] = ci.SupportGroup
	data["assigned_to"] = ci.AssignedTo
	data["serial_number"] = ci.SerialNumber
	data["asset_tag"] = ci.AssetTag
	data["model_id"] = ci.ModelID
	data["model_number"] = ci.ModelNumber
	data["manufacturer"] = ci.Manufacturer
	data["vendor"] = ci.Vendor
	data["short_description"] = ci.ShortDescription
	data["description"] = ci.Description
	data["ip_address"] = ci.IPAddress
	data["mac_address"] = ci.MacAddress
	data["fqdn"] = ci.FQDN
	data["dns_domain"] = ci.DNSDomain
	data["os"] = ci.OSName
	data["os_version"] = ci.OSVersion
	data["os_service_pack"] = ci.OSServicePack
	data["cpu_count"] = ci.CPUCount
	data["cpu_speed"] = ci.CPUSpeed
	data["cpu_type"] = ci.CPUType
	data["ram"] = ci.RAM
	data["disk_space"] = ci.DiskSpace
	data["cost_center"] = ci.CostCenter
	data["business_service"] = ci.BusinessService
	data["application"] = ci.Application

	// Add attributes
	for k, v := range ci.Attributes {
		data[k] = v
	}

	return data
}

// getItemKey generates a key for an item for tracking purposes
func (r *ReconciliationClient) getItemKey(item map[string]interface{}) string {
	if name, ok := item["name"].(string); ok && name != "" {
		return name
	}
	if serialNumber, ok := item["serial_number"].(string); ok && serialNumber != "" {
		return serialNumber
	}
	if assetTag, ok := item["asset_tag"].(string); ok && assetTag != "" {
		return assetTag
	}
	return "unknown"
}
