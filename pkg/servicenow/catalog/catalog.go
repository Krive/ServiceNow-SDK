package catalog

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"codeberg.org/Krive/ServiceNow-SDK/pkg/servicenow/core"
)

// CatalogClient handles ServiceNow Service Catalog API operations
type CatalogClient struct {
	client *core.Client
}

// NewCatalogClient creates a new service catalog client
func NewCatalogClient(client *core.Client) *CatalogClient {
	return &CatalogClient{
		client: client,
	}
}

// Catalog represents a ServiceNow catalog
type Catalog struct {
	SysID       string `json:"sys_id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Active      bool   `json:"active"`
	Background  string `json:"background_color"`
	Icon        string `json:"icon"`
}

// Category represents a catalog category
type Category struct {
	SysID        string `json:"sys_id"`
	Title        string `json:"title"`
	Description  string `json:"description"`
	Active       bool   `json:"active"`
	CatalogSysID string `json:"sc_catalog"`
	ParentSysID  string `json:"parent"`
	Icon         string `json:"icon"`
	Order        int    `json:"order"`
}

// CatalogItem represents a catalog item
type CatalogItem struct {
	SysID               string                 `json:"sys_id"`
	Name                string                 `json:"name"`
	ShortDescription    string                 `json:"short_description"`
	Description         string                 `json:"description"`
	Active              bool                   `json:"active"`
	CatalogSysID        string                 `json:"sc_catalog"`
	CategorySysID       string                 `json:"category"`
	Price               string                 `json:"price"`
	RecurringPrice      string                 `json:"recurring_price"`
	Icon                string                 `json:"icon"`
	Picture             string                 `json:"picture"`
	Type                string                 `json:"type"`
	Template            string                 `json:"template"`
	Workflow            string                 `json:"workflow"`
	Variables           []CatalogVariable      `json:"variables,omitempty"`
	AvailableFor        string                 `json:"available_for"`
	OrderGuide          bool                   `json:"order_guide"`
	RequestMethod       string                 `json:"request_method"`
	ApprovalDesignation string                 `json:"approval_designation"`
	DeliveryCatalog     string                 `json:"delivery_catalog"`
	ItemDetails         map[string]interface{} `json:"item_details,omitempty"`
}

// CatalogVariable represents a catalog item variable
type CatalogVariable struct {
	SysID          string                 `json:"sys_id"`
	Name           string                 `json:"name"`
	Question       string                 `json:"question"`
	Type           string                 `json:"type"`
	Mandatory      bool                   `json:"mandatory"`
	Active         bool                   `json:"active"`
	DefaultValue   string                 `json:"default_value"`
	HelpText       string                 `json:"help_text"`
	Order          int                    `json:"order"`
	ReadOnly       bool                   `json:"read_only"`
	Visible        bool                   `json:"visible"`
	ChoiceTable    string                 `json:"choice_table"`
	ChoiceField    string                 `json:"choice_field"`
	ReferenceTable string                 `json:"reference"`
	Choices        []VariableChoice       `json:"choices,omitempty"`
	Attributes     map[string]interface{} `json:"attributes,omitempty"`
}

// VariableChoice represents a choice for a variable
type VariableChoice struct {
	Value     string `json:"value"`
	Text      string `json:"text"`
	Dependent string `json:"dependent,omitempty"`
	Order     int    `json:"order"`
}

// ListCatalogs returns all available catalogs
func (cc *CatalogClient) ListCatalogs() ([]Catalog, error) {
	return cc.ListCatalogsWithContext(context.Background())
}

// ListCatalogsWithContext returns all available catalogs with context support
func (cc *CatalogClient) ListCatalogsWithContext(ctx context.Context) ([]Catalog, error) {
	params := map[string]string{
		"sysparm_query":  "active=true",
		"sysparm_fields": "sys_id,title,description,active,background_color,icon",
	}
	applyEncodedOrder(params, "order,title")

	var response core.Response
	err := cc.client.RawRequestWithContext(ctx, "GET", "/table/sc_catalog", nil, params, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to list catalogs: %w", err)
	}

	results, ok := response.Result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response format for catalogs")
	}

	catalogs := make([]Catalog, 0, len(results))
	for _, result := range results {
		catalogData, ok := result.(map[string]interface{})
		if !ok {
			continue
		}

		catalog := Catalog{
			SysID:       getString(catalogData["sys_id"]),
			Title:       getString(catalogData["title"]),
			Description: getString(catalogData["description"]),
			Active:      getBool(catalogData["active"]),
			Background:  getString(catalogData["background_color"]),
			Icon:        getString(catalogData["icon"]),
		}
		catalogs = append(catalogs, catalog)
	}

	return catalogs, nil
}

// GetCatalog returns a specific catalog by sys_id
func (cc *CatalogClient) GetCatalog(sysID string) (*Catalog, error) {
	return cc.GetCatalogWithContext(context.Background(), sysID)
}

// GetCatalogWithContext returns a specific catalog by sys_id with context support
func (cc *CatalogClient) GetCatalogWithContext(ctx context.Context, sysID string) (*Catalog, error) {
	var response core.Response
	err := cc.client.RawRequestWithContext(ctx, "GET", fmt.Sprintf("/table/sc_catalog/%s", escapeCatalogPathSegment(sysID)), nil, nil, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to get catalog: %w", err)
	}

	catalogData, ok := response.Result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response format for catalog")
	}

	catalog := &Catalog{
		SysID:       getString(catalogData["sys_id"]),
		Title:       getString(catalogData["title"]),
		Description: getString(catalogData["description"]),
		Active:      getBool(catalogData["active"]),
		Background:  getString(catalogData["background_color"]),
		Icon:        getString(catalogData["icon"]),
	}

	return catalog, nil
}

// ListCategories returns categories for a catalog
func (cc *CatalogClient) ListCategories(catalogSysID string) ([]Category, error) {
	return cc.ListCategoriesWithContext(context.Background(), catalogSysID)
}

// ListCategoriesWithContext returns categories for a catalog with context support
func (cc *CatalogClient) ListCategoriesWithContext(ctx context.Context, catalogSysID string) ([]Category, error) {
	sanitizedCatalogSysID := sanitizeQueryTerm(catalogSysID)
	params := map[string]string{
		"sysparm_query":  fmt.Sprintf("sc_catalog=%s^active=true", sanitizedCatalogSysID),
		"sysparm_fields": "sys_id,title,description,active,sc_catalog,parent,icon,order",
	}
	applyEncodedOrder(params, "order,title")

	var response core.Response
	err := cc.client.RawRequestWithContext(ctx, "GET", "/table/sc_cat_item_category", nil, params, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to list categories: %w", err)
	}

	results, ok := response.Result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response format for categories")
	}

	categories := make([]Category, 0, len(results))
	for _, result := range results {
		categoryData, ok := result.(map[string]interface{})
		if !ok {
			continue
		}

		category := Category{
			SysID:        getString(categoryData["sys_id"]),
			Title:        getString(categoryData["title"]),
			Description:  getString(categoryData["description"]),
			Active:       getBool(categoryData["active"]),
			CatalogSysID: getString(categoryData["sc_catalog"]),
			ParentSysID:  getString(categoryData["parent"]),
			Icon:         getString(categoryData["icon"]),
			Order:        getInt(categoryData["order"]),
		}
		categories = append(categories, category)
	}

	return categories, nil
}

// ListAllCategories returns all active categories across all catalogs
func (cc *CatalogClient) ListAllCategories() ([]Category, error) {
	return cc.ListAllCategoriesWithContext(context.Background())
}

// ListAllCategoriesWithContext returns all active categories with context support
func (cc *CatalogClient) ListAllCategoriesWithContext(ctx context.Context) ([]Category, error) {
	params := map[string]string{
		"sysparm_query":  "active=true",
		"sysparm_fields": "sys_id,title,description,active,sc_catalog,parent,icon,order",
	}
	applyEncodedOrder(params, "sc_catalog,order,title")

	var response core.Response
	err := cc.client.RawRequestWithContext(ctx, "GET", "/table/sc_cat_item_category", nil, params, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to list all categories: %w", err)
	}

	results, ok := response.Result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response format for categories")
	}

	categories := make([]Category, 0, len(results))
	for _, result := range results {
		categoryData, ok := result.(map[string]interface{})
		if !ok {
			continue
		}

		category := Category{
			SysID:        getString(categoryData["sys_id"]),
			Title:        getString(categoryData["title"]),
			Description:  getString(categoryData["description"]),
			Active:       getBool(categoryData["active"]),
			CatalogSysID: getString(categoryData["sc_catalog"]),
			ParentSysID:  getString(categoryData["parent"]),
			Icon:         getString(categoryData["icon"]),
			Order:        getInt(categoryData["order"]),
		}
		categories = append(categories, category)
	}

	return categories, nil
}

// GetCategory returns a specific category by sys_id
func (cc *CatalogClient) GetCategory(sysID string) (*Category, error) {
	return cc.GetCategoryWithContext(context.Background(), sysID)
}

// GetCategoryWithContext returns a specific category by sys_id with context support
func (cc *CatalogClient) GetCategoryWithContext(ctx context.Context, sysID string) (*Category, error) {
	var response core.Response
	err := cc.client.RawRequestWithContext(ctx, "GET", fmt.Sprintf("/table/sc_cat_item_category/%s", escapeCatalogPathSegment(sysID)), nil, nil, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to get category: %w", err)
	}

	categoryData, ok := response.Result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response format for category")
	}

	category := &Category{
		SysID:        getString(categoryData["sys_id"]),
		Title:        getString(categoryData["title"]),
		Description:  getString(categoryData["description"]),
		Active:       getBool(categoryData["active"]),
		CatalogSysID: getString(categoryData["sc_catalog"]),
		ParentSysID:  getString(categoryData["parent"]),
		Icon:         getString(categoryData["icon"]),
		Order:        getInt(categoryData["order"]),
	}

	return category, nil
}

// SearchCategories searches categories by title or description
func (cc *CatalogClient) SearchCategories(searchTerm string) ([]Category, error) {
	return cc.SearchCategoriesWithContext(context.Background(), searchTerm)
}

// SearchCategoriesWithContext searches categories with context support
func (cc *CatalogClient) SearchCategoriesWithContext(ctx context.Context, searchTerm string) ([]Category, error) {
	cleanSearchTerm := sanitizeQueryTerm(searchTerm)
	params := map[string]string{
		"sysparm_query":  fmt.Sprintf("active=true^titleCONTAINS%s^ORdescriptionCONTAINS%s", cleanSearchTerm, cleanSearchTerm),
		"sysparm_fields": "sys_id,title,description,active,sc_catalog,parent,icon,order",
	}
	applyEncodedOrder(params, "title")

	var response core.Response
	err := cc.client.RawRequestWithContext(ctx, "GET", "/table/sc_cat_item_category", nil, params, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to search categories: %w", err)
	}

	results, ok := response.Result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response format for category search")
	}

	categories := make([]Category, 0, len(results))
	for _, result := range results {
		categoryData, ok := result.(map[string]interface{})
		if !ok {
			continue
		}

		category := Category{
			SysID:        getString(categoryData["sys_id"]),
			Title:        getString(categoryData["title"]),
			Description:  getString(categoryData["description"]),
			Active:       getBool(categoryData["active"]),
			CatalogSysID: getString(categoryData["sc_catalog"]),
			ParentSysID:  getString(categoryData["parent"]),
			Icon:         getString(categoryData["icon"]),
			Order:        getInt(categoryData["order"]),
		}
		categories = append(categories, category)
	}

	return categories, nil
}

// Helper functions for type conversion
func getString(value interface{}) string {
	if str, ok := value.(string); ok {
		return str
	}
	return ""
}

func sanitizeQueryTerm(value string) string {
	cleaned := strings.ReplaceAll(value, "^", " ")
	cleaned = strings.ReplaceAll(cleaned, "\n", " ")
	cleaned = strings.ReplaceAll(cleaned, "\r", " ")
	return cleaned
}

func escapeCatalogPathSegment(value string) string {
	return url.PathEscape(strings.TrimSpace(value))
}

func getBool(value interface{}) bool {
	if b, ok := value.(bool); ok {
		return b
	}
	if str, ok := value.(string); ok {
		return str == "true"
	}
	return false
}

func getInt(value interface{}) int {
	if i, ok := value.(int); ok {
		return i
	}
	if f, ok := value.(float64); ok {
		return int(f)
	}
	if str, ok := value.(string); ok {
		if str == "" {
			return 0
		}
		if i, err := strconv.Atoi(str); err == nil {
			return i
		}
		return 0
	}
	return 0
}
