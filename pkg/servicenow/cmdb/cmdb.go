package cmdb

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Krive/ServiceNow-SDK/pkg/servicenow/core"
)

// CMDBClient provides methods for managing Configuration Items and CMDB operations
type CMDBClient struct {
	client *core.Client
}

func buildCMDBTablePath(tableName string) string {
	return fmt.Sprintf("/table/%s", url.PathEscape(strings.TrimSpace(tableName)))
}

func buildCMDBRecordPath(tableName, sysID string) string {
	return fmt.Sprintf(
		"/table/%s/%s",
		url.PathEscape(strings.TrimSpace(tableName)),
		url.PathEscape(strings.TrimSpace(sysID)),
	)
}

// ConfigurationItem represents a Configuration Item in ServiceNow
type ConfigurationItem struct {
	SysID                  string                 `json:"sys_id"`
	Name                   string                 `json:"name"`
	SysClassName           string                 `json:"sys_class_name"`
	State                  string                 `json:"install_status"`
	OperationalStatus      string                 `json:"operational_status"`
	Category               string                 `json:"category"`
	Subcategory            string                 `json:"subcategory"`
	Environment            string                 `json:"environment"`
	Location               string                 `json:"location"`
	Owner                  string                 `json:"owned_by"`
	SupportGroup           string                 `json:"support_group"`
	AssignedTo             string                 `json:"assigned_to"`
	SerialNumber           string                 `json:"serial_number"`
	AssetTag               string                 `json:"asset_tag"`
	ModelID                string                 `json:"model_id"`
	ModelNumber            string                 `json:"model_number"`
	Manufacturer           string                 `json:"manufacturer"`
	Vendor                 string                 `json:"vendor"`
	ShortDescription       string                 `json:"short_description"`
	Description            string                 `json:"description"`
	IPAddress              string                 `json:"ip_address"`
	MacAddress             string                 `json:"mac_address"`
	FQDN                   string                 `json:"fqdn"`
	DNSDomain              string                 `json:"dns_domain"`
	OSName                 string                 `json:"os"`
	OSVersion              string                 `json:"os_version"`
	OSServicePack          string                 `json:"os_service_pack"`
	CPUCount               int                    `json:"cpu_count"`
	CPUSpeed               string                 `json:"cpu_speed"`
	CPUType                string                 `json:"cpu_type"`
	RAM                    string                 `json:"ram"`
	DiskSpace              string                 `json:"disk_space"`
	CostCenter             string                 `json:"cost_center"`
	PurchaseDate           time.Time              `json:"purchase_date"`
	WarrantyExpiration     time.Time              `json:"warranty_expiration"`
	LeaseID                string                 `json:"lease_id"`
	CostCC                 string                 `json:"cost"`
	Depreciation           string                 `json:"depreciation"`
	SalvageValue           string                 `json:"salvage_value"`
	FirstDiscovered        time.Time              `json:"first_discovered"`
	LastDiscovered         time.Time              `json:"last_discovered"`
	DiscoverySource        string                 `json:"discovery_source"`
	Attributes             map[string]interface{} `json:"attributes,omitempty"`
	BusinessService        string                 `json:"business_service"`
	Application            string                 `json:"application"`
	ChangeControl          string                 `json:"change_control"`
	MaintenanceSchedule    string                 `json:"maintenance_schedule"`
	MonitoringTool         string                 `json:"monitoring_tool"`
	BackupTool             string                 `json:"backup_tool"`
	AntivirusSoftware      string                 `json:"antivirus_software"`
	PatchGroup             string                 `json:"patch_group"`
	ComplianceStatus       string                 `json:"compliance_status"`
	SecurityClassification string                 `json:"security_classification"`
	CreatedBy              string                 `json:"sys_created_by"`
	CreatedOn              time.Time              `json:"sys_created_on"`
	UpdatedBy              string                 `json:"sys_updated_by"`
	UpdatedOn              time.Time              `json:"sys_updated_on"`
}

// CIRelationship represents a relationship between Configuration Items
type CIRelationship struct {
	SysID            string                 `json:"sys_id"`
	Parent           string                 `json:"parent"`
	Child            string                 `json:"child"`
	Type             string                 `json:"type"`
	ConnectionType   string                 `json:"connection_type"`
	ParentDescriptor string                 `json:"parent_descriptor"`
	ChildDescriptor  string                 `json:"child_descriptor"`
	Direction        string                 `json:"direction"`
	Weight           int                    `json:"weight"`
	Attributes       map[string]interface{} `json:"attributes,omitempty"`
	CreatedBy        string                 `json:"sys_created_by"`
	CreatedOn        time.Time              `json:"sys_created_on"`
	UpdatedBy        string                 `json:"sys_updated_by"`
	UpdatedOn        time.Time              `json:"sys_updated_on"`
}

// CIClass represents a Configuration Item class definition
type CIClass struct {
	SysID        string    `json:"sys_id"`
	Name         string    `json:"name"`
	Label        string    `json:"label"`
	SuperClass   string    `json:"super_class"`
	TableName    string    `json:"table_name"`
	Package      string    `json:"sys_package"`
	Active       bool      `json:"active"`
	Abstract     bool      `json:"abstract"`
	Extensible   bool      `json:"extensible"`
	NumberPrefix string    `json:"number_ref"`
	Attributes   []string  `json:"attributes,omitempty"`
	Description  string    `json:"sys_documentation"`
	CreatedBy    string    `json:"sys_created_by"`
	CreatedOn    time.Time `json:"sys_created_on"`
	UpdatedBy    string    `json:"sys_updated_by"`
	UpdatedOn    time.Time `json:"sys_updated_on"`
}

// CIDependencyMap represents a dependency mapping for a CI
type CIDependencyMap struct {
	RootCI        *ConfigurationItem   `json:"root_ci"`
	Dependencies  []*ConfigurationItem `json:"dependencies"`
	Dependents    []*ConfigurationItem `json:"dependents"`
	Relationships []*CIRelationship    `json:"relationships"`
	Depth         int                  `json:"depth"`
}

// CIFilter provides filtering options for CI queries
type CIFilter struct {
	Class             string    `json:"class,omitempty"`
	State             string    `json:"state,omitempty"`
	OperationalStatus string    `json:"operational_status,omitempty"`
	Environment       string    `json:"environment,omitempty"`
	Location          string    `json:"location,omitempty"`
	Owner             string    `json:"owner,omitempty"`
	SupportGroup      string    `json:"support_group,omitempty"`
	SerialNumber      string    `json:"serial_number,omitempty"`
	AssetTag          string    `json:"asset_tag,omitempty"`
	IPAddress         string    `json:"ip_address,omitempty"`
	FQDN              string    `json:"fqdn,omitempty"`
	Name              string    `json:"name,omitempty"`
	CreatedAfter      time.Time `json:"created_after,omitempty"`
	CreatedBefore     time.Time `json:"created_before,omitempty"`
	UpdatedAfter      time.Time `json:"updated_after,omitempty"`
	UpdatedBefore     time.Time `json:"updated_before,omitempty"`
	Limit             int       `json:"limit,omitempty"`
	Offset            int       `json:"offset,omitempty"`
	OrderBy           string    `json:"order_by,omitempty"`
	Fields            []string  `json:"fields,omitempty"`
}

// CIReconciliationRequest contains options for CI reconciliation
type CIReconciliationRequest struct {
	Items      []map[string]interface{} `json:"items"`
	DataSource string                   `json:"data_source"`
	Options    *ReconciliationOptions   `json:"options,omitempty"`
}

// ReconciliationOptions contains options for CI reconciliation
type ReconciliationOptions struct {
	CreateMissing      bool     `json:"create_missing"`
	UpdateExisting     bool     `json:"update_existing"`
	MatchingRules      []string `json:"matching_rules,omitempty"`
	ConflictResolution string   `json:"conflict_resolution"`
	DryRun             bool     `json:"dry_run"`
	ClassName          string   `json:"class_name,omitempty"`
}

// CIReconciliationResult contains the result of CI reconciliation
type CIReconciliationResult struct {
	Created      []*ConfigurationItem  `json:"created"`
	Updated      []*ConfigurationItem  `json:"updated"`
	Skipped      []string              `json:"skipped"`
	Errors       []ReconciliationError `json:"errors"`
	TotalItems   int                   `json:"total_items"`
	SuccessCount int                   `json:"success_count"`
	ErrorCount   int                   `json:"error_count"`
	SkippedCount int                   `json:"skipped_count"`
}

// ReconciliationError represents an error during reconciliation
type ReconciliationError struct {
	Item    map[string]interface{} `json:"item"`
	Error   string                 `json:"error"`
	Code    string                 `json:"code"`
	Details string                 `json:"details,omitempty"`
}

// CIIdentificationRequest contains data for CI identification
type CIIdentificationRequest struct {
	Items   []map[string]interface{} `json:"items"`
	Options *IdentificationOptions   `json:"options,omitempty"`
}

// IdentificationOptions contains options for CI identification
type IdentificationOptions struct {
	MatchingAttributes []string `json:"matching_attributes,omitempty"`
	Threshold          float64  `json:"threshold,omitempty"`
	Strategy           string   `json:"strategy"`
	ClassName          string   `json:"class_name,omitempty"`
}

// CIIdentificationResult contains the result of CI identification
type CIIdentificationResult struct {
	Matches   []CIMatch                `json:"matches"`
	NoMatches []map[string]interface{} `json:"no_matches"`
}

// CIMatch represents a matched CI during identification
type CIMatch struct {
	InputItem map[string]interface{} `json:"input_item"`
	MatchedCI *ConfigurationItem     `json:"matched_ci"`
	Score     float64                `json:"score"`
	MatchedOn []string               `json:"matched_on"`
}

// NewCMDBClient creates a new CMDB client
func NewCMDBClient(client *core.Client) *CMDBClient {
	return &CMDBClient{client: client}
}

// GetCI retrieves a Configuration Item by sys_id
func (c *CMDBClient) GetCI(sysID string) (*ConfigurationItem, error) {
	return c.GetCIWithContext(context.Background(), sysID)
}

// GetCIWithContext retrieves a Configuration Item by sys_id with context support
func (c *CMDBClient) GetCIWithContext(ctx context.Context, sysID string) (*ConfigurationItem, error) {
	var lookup core.Response
	lookupParams := map[string]string{
		"sysparm_fields": "sys_id,sys_class_name",
	}
	err := c.client.RawRequestWithContext(ctx, "GET", buildCMDBRecordPath("cmdb_ci", sysID), nil, lookupParams, &lookup)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve CI class: %w", err)
	}

	lookupData, ok := lookup.Result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for CI class lookup: %T", lookup.Result)
	}

	className := extractReferenceString(lookupData["sys_class_name"])
	if className == "" {
		return nil, fmt.Errorf("sys_class_name not found for CI: %s", sysID)
	}

	var result core.Response
	err = c.client.RawRequestWithContext(ctx, "GET", fmt.Sprintf("/cmdb/instance/%s/%s", className, sysID), nil, nil, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to get CI: %w", err)
	}

	ciData, ok := result.Result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for CI get: %T", result.Result)
	}

	return c.mapDataToCI(ciData), nil
}

func extractReferenceString(value interface{}) string {
	switch v := value.(type) {
	case string:
		return v
	case map[string]interface{}:
		if raw, ok := v["value"].(string); ok && raw != "" {
			return raw
		}
		if display, ok := v["display_value"].(string); ok {
			return display
		}
	}
	return ""
}

// GetCIByClass retrieves a Configuration Item by class and sys_id
func (c *CMDBClient) GetCIByClass(className, sysID string) (*ConfigurationItem, error) {
	return c.GetCIByClassWithContext(context.Background(), className, sysID)
}

// GetCIByClassWithContext retrieves a Configuration Item by class and sys_id with context support
func (c *CMDBClient) GetCIByClassWithContext(ctx context.Context, className, sysID string) (*ConfigurationItem, error) {
	var result core.Response
	err := c.client.RawRequestWithContext(ctx, "GET", buildCMDBRecordPath(className, sysID), nil, nil, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to get CI by class: %w", err)
	}

	ciData, ok := result.Result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for CI get by class: %T", result.Result)
	}

	return c.mapDataToCI(ciData), nil
}

// ListCIs retrieves Configuration Items based on filter criteria
func (c *CMDBClient) ListCIs(filter *CIFilter) ([]*ConfigurationItem, error) {
	return c.ListCIsWithContext(context.Background(), filter)
}

// ListCIsWithContext retrieves Configuration Items based on filter criteria with context support
func (c *CMDBClient) ListCIsWithContext(ctx context.Context, filter *CIFilter) ([]*ConfigurationItem, error) {
	params := c.buildFilterParams(filter)

	tableName := "cmdb_ci"
	if filter != nil && filter.Class != "" {
		tableName = filter.Class
	}

	var result core.Response
	err := c.client.RawRequestWithContext(ctx, "GET", buildCMDBTablePath(tableName), nil, params, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to list CIs: %w", err)
	}

	results, ok := result.Result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for CI list: %T", result.Result)
	}

	var cis []*ConfigurationItem
	for _, r := range results {
		ciData, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		cis = append(cis, c.mapDataToCI(ciData))
	}

	return cis, nil
}

// CreateCI creates a new Configuration Item
func (c *CMDBClient) CreateCI(className string, ciData map[string]interface{}) (*ConfigurationItem, error) {
	return c.CreateCIWithContext(context.Background(), className, ciData)
}

// CreateCIWithContext creates a new Configuration Item with context support
func (c *CMDBClient) CreateCIWithContext(ctx context.Context, className string, ciData map[string]interface{}) (*ConfigurationItem, error) {
	var result core.Response
	err := c.client.RawRequestWithContext(ctx, "POST", buildCMDBTablePath(className), ciData, nil, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to create CI: %w", err)
	}

	resultData, ok := result.Result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for CI create: %T", result.Result)
	}

	return c.mapDataToCI(resultData), nil
}

// UpdateCI updates an existing Configuration Item
func (c *CMDBClient) UpdateCI(className, sysID string, updates map[string]interface{}) (*ConfigurationItem, error) {
	return c.UpdateCIWithContext(context.Background(), className, sysID, updates)
}

// UpdateCIWithContext updates an existing Configuration Item with context support
func (c *CMDBClient) UpdateCIWithContext(ctx context.Context, className, sysID string, updates map[string]interface{}) (*ConfigurationItem, error) {
	var result core.Response
	err := c.client.RawRequestWithContext(ctx, "PUT", buildCMDBRecordPath(className, sysID), updates, nil, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to update CI: %w", err)
	}

	resultData, ok := result.Result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for CI update: %T", result.Result)
	}

	return c.mapDataToCI(resultData), nil
}

// DeleteCI removes a Configuration Item
func (c *CMDBClient) DeleteCI(className, sysID string) error {
	return c.DeleteCIWithContext(context.Background(), className, sysID)
}

// DeleteCIWithContext removes a Configuration Item with context support
func (c *CMDBClient) DeleteCIWithContext(ctx context.Context, className, sysID string) error {
	err := c.client.RawRequestWithContext(ctx, "DELETE", buildCMDBRecordPath(className, sysID), nil, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to delete CI: %w", err)
	}
	return nil
}

// Helper method to build filter parameters
func (c *CMDBClient) buildFilterParams(filter *CIFilter) map[string]string {
	params := make(map[string]string)

	if filter == nil {
		return params
	}

	var queryParts []string

	if filter.State != "" {
		queryParts = append(queryParts, fmt.Sprintf("install_status=%s", sanitizeEncodedQueryValue(filter.State)))
	}
	if filter.OperationalStatus != "" {
		queryParts = append(queryParts, fmt.Sprintf("operational_status=%s", sanitizeEncodedQueryValue(filter.OperationalStatus)))
	}
	if filter.Environment != "" {
		queryParts = append(queryParts, fmt.Sprintf("environment=%s", sanitizeEncodedQueryValue(filter.Environment)))
	}
	if filter.Location != "" {
		queryParts = append(queryParts, fmt.Sprintf("location=%s", sanitizeEncodedQueryValue(filter.Location)))
	}
	if filter.Owner != "" {
		queryParts = append(queryParts, fmt.Sprintf("owned_by=%s", sanitizeEncodedQueryValue(filter.Owner)))
	}
	if filter.SupportGroup != "" {
		queryParts = append(queryParts, fmt.Sprintf("support_group=%s", sanitizeEncodedQueryValue(filter.SupportGroup)))
	}
	if filter.SerialNumber != "" {
		queryParts = append(queryParts, fmt.Sprintf("serial_number=%s", sanitizeEncodedQueryValue(filter.SerialNumber)))
	}
	if filter.AssetTag != "" {
		queryParts = append(queryParts, fmt.Sprintf("asset_tag=%s", sanitizeEncodedQueryValue(filter.AssetTag)))
	}
	if filter.IPAddress != "" {
		queryParts = append(queryParts, fmt.Sprintf("ip_address=%s", sanitizeEncodedQueryValue(filter.IPAddress)))
	}
	if filter.FQDN != "" {
		queryParts = append(queryParts, fmt.Sprintf("fqdn=%s", sanitizeEncodedQueryValue(filter.FQDN)))
	}
	if filter.Name != "" {
		queryParts = append(queryParts, fmt.Sprintf("nameLIKE%s", sanitizeEncodedQueryValue(filter.Name)))
	}
	if !filter.CreatedAfter.IsZero() {
		queryParts = append(queryParts, fmt.Sprintf("sys_created_on>=%s", formatEncodedQueryDateTime(filter.CreatedAfter)))
	}
	if !filter.CreatedBefore.IsZero() {
		queryParts = append(queryParts, fmt.Sprintf("sys_created_on<=%s", formatEncodedQueryDateTime(filter.CreatedBefore)))
	}
	if !filter.UpdatedAfter.IsZero() {
		queryParts = append(queryParts, fmt.Sprintf("sys_updated_on>=%s", formatEncodedQueryDateTime(filter.UpdatedAfter)))
	}
	if !filter.UpdatedBefore.IsZero() {
		queryParts = append(queryParts, fmt.Sprintf("sys_updated_on<=%s", formatEncodedQueryDateTime(filter.UpdatedBefore)))
	}

	if len(queryParts) > 0 {
		params["sysparm_query"] = strings.Join(queryParts, "^")
	}

	if filter.Limit > 0 {
		params["sysparm_limit"] = fmt.Sprintf("%d", filter.Limit)
	}
	if filter.Offset > 0 {
		params["sysparm_offset"] = fmt.Sprintf("%d", filter.Offset)
	}
	if orderClause := buildEncodedOrderClause(filter.OrderBy); orderClause != "" {
		queryParts = append(queryParts, orderClause)
		params["sysparm_query"] = strings.Join(queryParts, "^")
	}
	if len(filter.Fields) > 0 {
		params["sysparm_fields"] = strings.Join(filter.Fields, ",")
	}

	return params
}

func buildEncodedOrderClause(orderBy string) string {
	order := strings.TrimSpace(orderBy)
	if order == "" {
		return ""
	}

	desc := false
	upper := strings.ToUpper(order)
	switch {
	case strings.HasPrefix(order, "-"):
		desc = true
		order = strings.TrimSpace(order[1:])
	case strings.HasPrefix(upper, "DESC "):
		desc = true
		order = strings.TrimSpace(order[5:])
	case strings.HasPrefix(upper, "ASC "):
		order = strings.TrimSpace(order[4:])
	}

	if order == "" {
		return ""
	}
	order = sanitizeEncodedQueryValue(order)

	if desc {
		return "ORDERBYDESC" + order
	}
	return "ORDERBY" + order
}

// Helper method to map raw data to ConfigurationItem struct
func (c *CMDBClient) mapDataToCI(data map[string]interface{}) *ConfigurationItem {
	ci := &ConfigurationItem{
		Attributes: make(map[string]interface{}),
	}

	// Map standard fields
	if sysID, ok := data["sys_id"].(string); ok {
		ci.SysID = sysID
	}
	if name, ok := data["name"].(string); ok {
		ci.Name = name
	}
	if className, ok := data["sys_class_name"].(string); ok {
		ci.SysClassName = className
	}
	if state, ok := data["install_status"].(string); ok {
		ci.State = state
	}
	if opStatus, ok := data["operational_status"].(string); ok {
		ci.OperationalStatus = opStatus
	}
	if category, ok := data["category"].(string); ok {
		ci.Category = category
	}
	if subcategory, ok := data["subcategory"].(string); ok {
		ci.Subcategory = subcategory
	}
	if environment, ok := data["environment"].(string); ok {
		ci.Environment = environment
	}
	if location, ok := data["location"].(string); ok {
		ci.Location = location
	}
	if owner, ok := data["owned_by"].(string); ok {
		ci.Owner = owner
	}
	if supportGroup, ok := data["support_group"].(string); ok {
		ci.SupportGroup = supportGroup
	}
	if assignedTo, ok := data["assigned_to"].(string); ok {
		ci.AssignedTo = assignedTo
	}
	if serialNumber, ok := data["serial_number"].(string); ok {
		ci.SerialNumber = serialNumber
	}
	if assetTag, ok := data["asset_tag"].(string); ok {
		ci.AssetTag = assetTag
	}
	if modelID, ok := data["model_id"].(string); ok {
		ci.ModelID = modelID
	}
	if modelNumber, ok := data["model_number"].(string); ok {
		ci.ModelNumber = modelNumber
	}
	if manufacturer, ok := data["manufacturer"].(string); ok {
		ci.Manufacturer = manufacturer
	}
	if vendor, ok := data["vendor"].(string); ok {
		ci.Vendor = vendor
	}
	if shortDesc, ok := data["short_description"].(string); ok {
		ci.ShortDescription = shortDesc
	}
	if description, ok := data["description"].(string); ok {
		ci.Description = description
	}
	if ipAddress, ok := data["ip_address"].(string); ok {
		ci.IPAddress = ipAddress
	}
	if macAddress, ok := data["mac_address"].(string); ok {
		ci.MacAddress = macAddress
	}
	if fqdn, ok := data["fqdn"].(string); ok {
		ci.FQDN = fqdn
	}
	if dnsDomain, ok := data["dns_domain"].(string); ok {
		ci.DNSDomain = dnsDomain
	}
	if osName, ok := data["os"].(string); ok {
		ci.OSName = osName
	}
	if osVersion, ok := data["os_version"].(string); ok {
		ci.OSVersion = osVersion
	}
	if osServicePack, ok := data["os_service_pack"].(string); ok {
		ci.OSServicePack = osServicePack
	}
	if cpuCount, ok := data["cpu_count"].(string); ok {
		if count, err := fmt.Sscanf(cpuCount, "%d", &ci.CPUCount); err == nil && count == 1 {
			// Successfully parsed
		}
	}
	if cpuSpeed, ok := data["cpu_speed"].(string); ok {
		ci.CPUSpeed = cpuSpeed
	}
	if cpuType, ok := data["cpu_type"].(string); ok {
		ci.CPUType = cpuType
	}
	if ram, ok := data["ram"].(string); ok {
		ci.RAM = ram
	}
	if diskSpace, ok := data["disk_space"].(string); ok {
		ci.DiskSpace = diskSpace
	}
	if costCenter, ok := data["cost_center"].(string); ok {
		ci.CostCenter = costCenter
	}
	if cost, ok := data["cost"].(string); ok {
		ci.CostCC = cost
	}
	if depreciation, ok := data["depreciation"].(string); ok {
		ci.Depreciation = depreciation
	}
	if salvageValue, ok := data["salvage_value"].(string); ok {
		ci.SalvageValue = salvageValue
	}
	if leaseID, ok := data["lease_id"].(string); ok {
		ci.LeaseID = leaseID
	}
	if businessService, ok := data["business_service"].(string); ok {
		ci.BusinessService = businessService
	}
	if application, ok := data["application"].(string); ok {
		ci.Application = application
	}
	if changeControl, ok := data["change_control"].(string); ok {
		ci.ChangeControl = changeControl
	}
	if maintenanceSchedule, ok := data["maintenance_schedule"].(string); ok {
		ci.MaintenanceSchedule = maintenanceSchedule
	}
	if monitoringTool, ok := data["monitoring_tool"].(string); ok {
		ci.MonitoringTool = monitoringTool
	}
	if backupTool, ok := data["backup_tool"].(string); ok {
		ci.BackupTool = backupTool
	}
	if antivirusSoftware, ok := data["antivirus_software"].(string); ok {
		ci.AntivirusSoftware = antivirusSoftware
	}
	if patchGroup, ok := data["patch_group"].(string); ok {
		ci.PatchGroup = patchGroup
	}
	if complianceStatus, ok := data["compliance_status"].(string); ok {
		ci.ComplianceStatus = complianceStatus
	}
	if securityClassification, ok := data["security_classification"].(string); ok {
		ci.SecurityClassification = securityClassification
	}
	if discoverySource, ok := data["discovery_source"].(string); ok {
		ci.DiscoverySource = discoverySource
	}
	if createdBy, ok := data["sys_created_by"].(string); ok {
		ci.CreatedBy = createdBy
	}
	if updatedBy, ok := data["sys_updated_by"].(string); ok {
		ci.UpdatedBy = updatedBy
	}

	// Parse timestamps
	if createdOn, ok := data["sys_created_on"].(string); ok {
		if t, err := time.Parse("2006-01-02 15:04:05", createdOn); err == nil {
			ci.CreatedOn = t
		}
	}
	if updatedOn, ok := data["sys_updated_on"].(string); ok {
		if t, err := time.Parse("2006-01-02 15:04:05", updatedOn); err == nil {
			ci.UpdatedOn = t
		}
	}
	if purchaseDate, ok := data["purchase_date"].(string); ok {
		if t, err := time.Parse("2006-01-02", purchaseDate); err == nil {
			ci.PurchaseDate = t
		}
	}
	if warrantyExpiration, ok := data["warranty_expiration"].(string); ok {
		if t, err := time.Parse("2006-01-02", warrantyExpiration); err == nil {
			ci.WarrantyExpiration = t
		}
	}
	if firstDiscovered, ok := data["first_discovered"].(string); ok {
		if t, err := time.Parse("2006-01-02 15:04:05", firstDiscovered); err == nil {
			ci.FirstDiscovered = t
		}
	}
	if lastDiscovered, ok := data["last_discovered"].(string); ok {
		if t, err := time.Parse("2006-01-02 15:04:05", lastDiscovered); err == nil {
			ci.LastDiscovered = t
		}
	}

	// Store any additional attributes that weren't mapped
	standardFields := map[string]bool{
		"sys_id": true, "name": true, "sys_class_name": true, "install_status": true,
		"operational_status": true, "category": true, "subcategory": true, "environment": true,
		"location": true, "owned_by": true, "support_group": true, "assigned_to": true,
		"serial_number": true, "asset_tag": true, "model_id": true, "model_number": true,
		"manufacturer": true, "vendor": true, "short_description": true, "description": true,
		"ip_address": true, "mac_address": true, "fqdn": true, "dns_domain": true, "os": true,
		"os_version": true, "os_service_pack": true, "cpu_count": true, "cpu_speed": true,
		"cpu_type": true, "ram": true, "disk_space": true, "cost_center": true, "cost": true,
		"depreciation": true, "salvage_value": true, "lease_id": true, "business_service": true,
		"application": true, "change_control": true, "maintenance_schedule": true,
		"monitoring_tool": true, "backup_tool": true, "antivirus_software": true,
		"patch_group": true, "compliance_status": true, "security_classification": true,
		"discovery_source": true, "sys_created_by": true, "sys_updated_by": true,
		"sys_created_on": true, "sys_updated_on": true, "purchase_date": true,
		"warranty_expiration": true, "first_discovered": true, "last_discovered": true,
	}

	for key, value := range data {
		if !standardFields[key] {
			ci.Attributes[key] = value
		}
	}

	return ci
}
