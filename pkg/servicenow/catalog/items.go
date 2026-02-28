package catalog

import (
	"context"
	"fmt"
	"strconv"

	"github.com/Krive/ServiceNow-SDK/pkg/servicenow/core"
)

// ListItems returns catalog items for a specific catalog
func (cc *CatalogClient) ListItems(catalogSysID string) ([]CatalogItem, error) {
	return cc.ListItemsWithContext(context.Background(), catalogSysID)
}

// ListItemsWithContext returns catalog items with context support
func (cc *CatalogClient) ListItemsWithContext(ctx context.Context, catalogSysID string) ([]CatalogItem, error) {
	sanitizedCatalogSysID := sanitizeQueryTerm(catalogSysID)
	params := map[string]string{
		"sysparm_query":  fmt.Sprintf("sc_catalog=%s^active=true", sanitizedCatalogSysID),
		"sysparm_fields": "sys_id,name,short_description,description,active,sc_catalog,category,price,recurring_price,icon,picture,type,template,workflow,available_for,order_guide,request_method,approval_designation,delivery_catalog",
	}
	applyEncodedOrder(params, "order,name")

	var response core.Response
	err := cc.client.RawRequestWithContext(ctx, "GET", "/table/sc_cat_item", nil, params, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to list catalog items: %w", err)
	}

	return cc.parseCatalogItems(response)
}

// ListItemsByCategory returns catalog items for a specific category
func (cc *CatalogClient) ListItemsByCategory(categorySysID string) ([]CatalogItem, error) {
	return cc.ListItemsByCategoryWithContext(context.Background(), categorySysID)
}

// ListItemsByCategoryWithContext returns catalog items by category with context support
func (cc *CatalogClient) ListItemsByCategoryWithContext(ctx context.Context, categorySysID string) ([]CatalogItem, error) {
	sanitizedCategorySysID := sanitizeQueryTerm(categorySysID)
	params := map[string]string{
		"sysparm_query":  fmt.Sprintf("category=%s^active=true", sanitizedCategorySysID),
		"sysparm_fields": "sys_id,name,short_description,description,active,sc_catalog,category,price,recurring_price,icon,picture,type,template,workflow,available_for,order_guide,request_method,approval_designation,delivery_catalog",
	}
	applyEncodedOrder(params, "order,name")

	var response core.Response
	err := cc.client.RawRequestWithContext(ctx, "GET", "/table/sc_cat_item", nil, params, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to list catalog items by category: %w", err)
	}

	return cc.parseCatalogItems(response)
}

// ListAllItems returns all active catalog items
func (cc *CatalogClient) ListAllItems() ([]CatalogItem, error) {
	return cc.ListAllItemsWithContext(context.Background())
}

// ListAllItemsWithContext returns all active catalog items with context support
func (cc *CatalogClient) ListAllItemsWithContext(ctx context.Context) ([]CatalogItem, error) {
	params := map[string]string{
		"sysparm_query":  "active=true",
		"sysparm_fields": "sys_id,name,short_description,description,active,sc_catalog,category,price,recurring_price,icon,picture,type,template,workflow,available_for,order_guide,request_method,approval_designation,delivery_catalog",
	}
	applyEncodedOrder(params, "sc_catalog,order,name")

	var response core.Response
	err := cc.client.RawRequestWithContext(ctx, "GET", "/table/sc_cat_item", nil, params, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to list all catalog items: %w", err)
	}

	return cc.parseCatalogItems(response)
}

// GetItem returns a specific catalog item by sys_id
func (cc *CatalogClient) GetItem(sysID string) (*CatalogItem, error) {
	return cc.GetItemWithContext(context.Background(), sysID)
}

// GetItemWithContext returns a specific catalog item by sys_id with context support
func (cc *CatalogClient) GetItemWithContext(ctx context.Context, sysID string) (*CatalogItem, error) {
	var response core.Response
	err := cc.client.RawRequestWithContext(ctx, "GET", fmt.Sprintf("/table/sc_cat_item/%s", escapeCatalogPathSegment(sysID)), nil, nil, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to get catalog item: %w", err)
	}

	itemData, ok := response.Result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response format for catalog item")
	}

	item := cc.parseCatalogItem(itemData)
	return &item, nil
}

// GetItemWithVariables returns a catalog item with its variables
func (cc *CatalogClient) GetItemWithVariables(sysID string) (*CatalogItem, error) {
	return cc.GetItemWithVariablesWithContext(context.Background(), sysID)
}

// GetItemWithVariablesWithContext returns a catalog item with variables and context support
func (cc *CatalogClient) GetItemWithVariablesWithContext(ctx context.Context, sysID string) (*CatalogItem, error) {
	// First get the item
	item, err := cc.GetItemWithContext(ctx, sysID)
	if err != nil {
		return nil, err
	}

	// Then get its variables
	variables, err := cc.GetItemVariablesWithContext(ctx, sysID)
	if err != nil {
		return nil, fmt.Errorf("failed to get item variables: %w", err)
	}

	item.Variables = variables
	return item, nil
}

// GetItemVariables returns variables for a catalog item
func (cc *CatalogClient) GetItemVariables(itemSysID string) ([]CatalogVariable, error) {
	return cc.GetItemVariablesWithContext(context.Background(), itemSysID)
}

// GetItemVariablesWithContext returns variables for a catalog item with context support
func (cc *CatalogClient) GetItemVariablesWithContext(ctx context.Context, itemSysID string) ([]CatalogVariable, error) {
	sanitizedItemSysID := sanitizeQueryTerm(itemSysID)
	params := map[string]string{
		"sysparm_query":  fmt.Sprintf("cat_item=%s^active=true", sanitizedItemSysID),
		"sysparm_fields": "sys_id,name,question,type,mandatory,active,default_value,help_text,order,read_only,visible,choice_table,choice_field,reference",
	}
	applyEncodedOrder(params, "order,name")

	var response core.Response
	err := cc.client.RawRequestWithContext(ctx, "GET", "/table/item_option_new", nil, params, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to get item variables: %w", err)
	}

	results, ok := response.Result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response format for variables")
	}

	variables := make([]CatalogVariable, 0, len(results))
	for _, result := range results {
		variableData, ok := result.(map[string]interface{})
		if !ok {
			continue
		}

		variable := CatalogVariable{
			SysID:          getString(variableData["sys_id"]),
			Name:           getString(variableData["name"]),
			Question:       getString(variableData["question"]),
			Type:           getString(variableData["type"]),
			Mandatory:      getBool(variableData["mandatory"]),
			Active:         getBool(variableData["active"]),
			DefaultValue:   getString(variableData["default_value"]),
			HelpText:       getString(variableData["help_text"]),
			Order:          getInt(variableData["order"]),
			ReadOnly:       getBool(variableData["read_only"]),
			Visible:        getBool(variableData["visible"]),
			ChoiceTable:    getString(variableData["choice_table"]),
			ChoiceField:    getString(variableData["choice_field"]),
			ReferenceTable: getString(variableData["reference"]),
		}

		// Get choices for choice-type variables
		if variable.Type == "choice" || variable.Type == "select_box" || variable.Type == "radio" {
			choices, err := cc.getVariableChoicesWithContext(ctx, variable.SysID)
			if err == nil {
				variable.Choices = choices
			}
		}

		variables = append(variables, variable)
	}

	return variables, nil
}

// getVariableChoicesWithContext returns choices for a variable
func (cc *CatalogClient) getVariableChoicesWithContext(ctx context.Context, variableSysID string) ([]VariableChoice, error) {
	sanitizedVariableSysID := sanitizeQueryTerm(variableSysID)
	params := map[string]string{
		"sysparm_query":  fmt.Sprintf("question=%s^inactive=false", sanitizedVariableSysID),
		"sysparm_fields": "value,text,dependent_value,order",
	}
	applyEncodedOrder(params, "order,text")

	var response core.Response
	err := cc.client.RawRequestWithContext(ctx, "GET", "/table/question_choice", nil, params, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to get variable choices: %w", err)
	}

	results, ok := response.Result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response format for choices")
	}

	choices := make([]VariableChoice, 0, len(results))
	for _, result := range results {
		choiceData, ok := result.(map[string]interface{})
		if !ok {
			continue
		}

		choice := VariableChoice{
			Value:     getString(choiceData["value"]),
			Text:      getString(choiceData["text"]),
			Dependent: getString(choiceData["dependent_value"]),
			Order:     getInt(choiceData["order"]),
		}
		choices = append(choices, choice)
	}

	return choices, nil
}

// SearchItems searches catalog items by name or description
func (cc *CatalogClient) SearchItems(searchTerm string) ([]CatalogItem, error) {
	return cc.SearchItemsWithContext(context.Background(), searchTerm)
}

// SearchItemsWithContext searches catalog items with context support
func (cc *CatalogClient) SearchItemsWithContext(ctx context.Context, searchTerm string) ([]CatalogItem, error) {
	cleanSearchTerm := sanitizeQueryTerm(searchTerm)
	params := map[string]string{
		"sysparm_query":  fmt.Sprintf("active=true^nameCONTAINS%s^ORshort_descriptionCONTAINS%s^ORdescriptionCONTAINS%s", cleanSearchTerm, cleanSearchTerm, cleanSearchTerm),
		"sysparm_fields": "sys_id,name,short_description,description,active,sc_catalog,category,price,recurring_price,icon,picture,type,template,workflow,available_for,order_guide,request_method,approval_designation,delivery_catalog",
	}
	applyEncodedOrder(params, "name")

	var response core.Response
	err := cc.client.RawRequestWithContext(ctx, "GET", "/table/sc_cat_item", nil, params, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to search catalog items: %w", err)
	}

	return cc.parseCatalogItems(response)
}

// GetItemsByType returns catalog items of a specific type
func (cc *CatalogClient) GetItemsByType(itemType string) ([]CatalogItem, error) {
	return cc.GetItemsByTypeWithContext(context.Background(), itemType)
}

// GetItemsByTypeWithContext returns catalog items by type with context support
func (cc *CatalogClient) GetItemsByTypeWithContext(ctx context.Context, itemType string) ([]CatalogItem, error) {
	sanitizedItemType := sanitizeQueryTerm(itemType)
	params := map[string]string{
		"sysparm_query":  fmt.Sprintf("active=true^type=%s", sanitizedItemType),
		"sysparm_fields": "sys_id,name,short_description,description,active,sc_catalog,category,price,recurring_price,icon,picture,type,template,workflow,available_for,order_guide,request_method,approval_designation,delivery_catalog",
	}
	applyEncodedOrder(params, "name")

	var response core.Response
	err := cc.client.RawRequestWithContext(ctx, "GET", "/table/sc_cat_item", nil, params, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to get items by type: %w", err)
	}

	return cc.parseCatalogItems(response)
}

// GetOrderGuides returns catalog items that are order guides
func (cc *CatalogClient) GetOrderGuides() ([]CatalogItem, error) {
	return cc.GetOrderGuidesWithContext(context.Background())
}

// GetOrderGuidesWithContext returns order guides with context support
func (cc *CatalogClient) GetOrderGuidesWithContext(ctx context.Context) ([]CatalogItem, error) {
	params := map[string]string{
		"sysparm_query":  "active=true^order_guide=true",
		"sysparm_fields": "sys_id,name,short_description,description,active,sc_catalog,category,price,recurring_price,icon,picture,type,template,workflow,available_for,order_guide,request_method,approval_designation,delivery_catalog",
	}
	applyEncodedOrder(params, "name")

	var response core.Response
	err := cc.client.RawRequestWithContext(ctx, "GET", "/table/sc_cat_item", nil, params, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to get order guides: %w", err)
	}

	return cc.parseCatalogItems(response)
}

// ValidateItemVariables validates variables for a catalog item
func (cc *CatalogClient) ValidateItemVariables(itemSysID string, variables map[string]interface{}) ([]ValidationError, error) {
	return cc.ValidateItemVariablesWithContext(context.Background(), itemSysID, variables)
}

// ValidateItemVariablesWithContext validates variables with context support
func (cc *CatalogClient) ValidateItemVariablesWithContext(ctx context.Context, itemSysID string, variables map[string]interface{}) ([]ValidationError, error) {
	// Get item variables
	itemVariables, err := cc.GetItemVariablesWithContext(ctx, itemSysID)
	if err != nil {
		return nil, fmt.Errorf("failed to get item variables for validation: %w", err)
	}

	var errors []ValidationError

	// Check mandatory variables
	for _, variable := range itemVariables {
		if variable.Mandatory && variable.Active {
			value, exists := variables[variable.Name]
			if !exists {
				errors = append(errors, ValidationError{
					Variable: variable.Name,
					Message:  fmt.Sprintf("Mandatory variable '%s' is missing", variable.Question),
					Type:     "missing_mandatory",
				})
				continue
			}

			// Check if value is empty
			if isEmptyValue(value) {
				errors = append(errors, ValidationError{
					Variable: variable.Name,
					Message:  fmt.Sprintf("Mandatory variable '%s' cannot be empty", variable.Question),
					Type:     "empty_mandatory",
				})
			}
		}

		// Validate choice variables
		if variable.Type == "choice" || variable.Type == "select_box" || variable.Type == "radio" {
			if value, exists := variables[variable.Name]; exists && !isEmptyValue(value) {
				if !cc.isValidChoice(variable.Choices, fmt.Sprintf("%v", value)) {
					errors = append(errors, ValidationError{
						Variable: variable.Name,
						Message:  fmt.Sprintf("Invalid choice '%v' for variable '%s'", value, variable.Question),
						Type:     "invalid_choice",
					})
				}
			}
		}
	}

	return errors, nil
}

// ValidationError represents a variable validation error
type ValidationError struct {
	Variable string `json:"variable"`
	Message  string `json:"message"`
	Type     string `json:"type"`
}

// Helper functions

func (cc *CatalogClient) parseCatalogItems(response core.Response) ([]CatalogItem, error) {
	results, ok := response.Result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response format for catalog items")
	}

	items := make([]CatalogItem, 0, len(results))
	for _, result := range results {
		itemData, ok := result.(map[string]interface{})
		if !ok {
			continue
		}

		item := cc.parseCatalogItem(itemData)
		items = append(items, item)
	}

	return items, nil
}

func (cc *CatalogClient) parseCatalogItem(itemData map[string]interface{}) CatalogItem {
	return CatalogItem{
		SysID:               getString(itemData["sys_id"]),
		Name:                getString(itemData["name"]),
		ShortDescription:    getString(itemData["short_description"]),
		Description:         getString(itemData["description"]),
		Active:              getBool(itemData["active"]),
		CatalogSysID:        getString(itemData["sc_catalog"]),
		CategorySysID:       getString(itemData["category"]),
		Price:               getString(itemData["price"]),
		RecurringPrice:      getString(itemData["recurring_price"]),
		Icon:                getString(itemData["icon"]),
		Picture:             getString(itemData["picture"]),
		Type:                getString(itemData["type"]),
		Template:            getString(itemData["template"]),
		Workflow:            getString(itemData["workflow"]),
		AvailableFor:        getString(itemData["available_for"]),
		OrderGuide:          getBool(itemData["order_guide"]),
		RequestMethod:       getString(itemData["request_method"]),
		ApprovalDesignation: getString(itemData["approval_designation"]),
		DeliveryCatalog:     getString(itemData["delivery_catalog"]),
	}
}

func (cc *CatalogClient) isValidChoice(choices []VariableChoice, value string) bool {
	for _, choice := range choices {
		if choice.Value == value {
			return true
		}
	}
	return false
}

func isEmptyValue(value interface{}) bool {
	if value == nil {
		return true
	}
	if str, ok := value.(string); ok {
		return str == ""
	}
	return false
}

// getFloat converts interface{} to float64
func getFloat(value interface{}) float64 {
	if f, ok := value.(float64); ok {
		return f
	}
	if i, ok := value.(int); ok {
		return float64(i)
	}
	if str, ok := value.(string); ok {
		if f, err := strconv.ParseFloat(str, 64); err == nil {
			return f
		}
	}
	return 0.0
}
