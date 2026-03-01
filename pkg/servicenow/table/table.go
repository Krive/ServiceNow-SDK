package table

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"codeberg.org/Krive/ServiceNow-SDK/pkg/servicenow/core"
	"codeberg.org/Krive/ServiceNow-SDK/pkg/servicenow/query"
)

type TableClient struct {
	client *core.Client
	name   string
}

func NewTableClient(client *core.Client, name string) *TableClient {
	return &TableClient{client: client, name: name}
}

func buildTablePath(tableName string) string {
	return fmt.Sprintf("/table/%s", url.PathEscape(strings.TrimSpace(tableName)))
}

func buildTableRecordPath(tableName, sysID string) string {
	return fmt.Sprintf(
		"/table/%s/%s",
		url.PathEscape(strings.TrimSpace(tableName)),
		url.PathEscape(strings.TrimSpace(sysID)),
	)
}

func buildTableStatsPath(tableName string) string {
	return fmt.Sprintf("/stats/%s", url.PathEscape(strings.TrimSpace(tableName)))
}

// List retrieves records from the table
func (t *TableClient) List(params map[string]string) ([]map[string]interface{}, error) {
	return t.ListWithContext(context.Background(), params)
}

// ListWithContext retrieves records from the table with context support
func (t *TableClient) ListWithContext(ctx context.Context, params map[string]string) ([]map[string]interface{}, error) {
	var result core.Response
	err := t.client.RawRequestWithContext(ctx, "GET", buildTablePath(t.name), nil, params, &result)
	if err != nil {
		return nil, err
	}
	results, ok := result.Result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for list: %T", result.Result)
	}
	var records []map[string]interface{}
	for _, r := range results {
		record, ok := r.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("unexpected record type: %T", r)
		}
		records = append(records, record)
	}
	return records, nil
}

// Get retrieves a single record by sys_id
func (t *TableClient) Get(sysID string) (map[string]interface{}, error) {
	return t.GetWithContext(context.Background(), sysID)
}

// GetWithContext retrieves a single record by sys_id with context support
func (t *TableClient) GetWithContext(ctx context.Context, sysID string) (map[string]interface{}, error) {
	var result core.Response
	err := t.client.RawRequestWithContext(ctx, "GET", buildTableRecordPath(t.name, sysID), nil, nil, &result)
	if err != nil {
		return nil, err
	}
	record, ok := result.Result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for get: %T", result.Result)
	}
	return record, nil
}

// Create inserts a new record using POST
func (t *TableClient) Create(record map[string]interface{}) (map[string]interface{}, error) {
	return t.CreateWithContext(context.Background(), record)
}

// CreateWithContext inserts a new record using POST with context support
func (t *TableClient) CreateWithContext(ctx context.Context, record map[string]interface{}) (map[string]interface{}, error) {
	var result core.Response
	err := t.client.RawRequestWithContext(ctx, "POST", buildTablePath(t.name), record, nil, &result)
	if err != nil {
		return nil, err
	}
	created, ok := result.Result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for create: %T", result.Result)
	}
	return created, nil
}

// Update performs a partial update using PATCH
func (t *TableClient) Update(sysID string, record map[string]interface{}) (map[string]interface{}, error) {
	return t.UpdateWithContext(context.Background(), sysID, record)
}

// UpdateWithContext performs a partial update using PATCH with context support
func (t *TableClient) UpdateWithContext(ctx context.Context, sysID string, record map[string]interface{}) (map[string]interface{}, error) {
	var result core.Response
	err := t.client.RawRequestWithContext(ctx, "PATCH", buildTableRecordPath(t.name, sysID), record, nil, &result)
	if err != nil {
		return nil, err
	}
	updated, ok := result.Result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for update: %T", result.Result)
	}
	return updated, nil
}

// Put performs a full replace using PUT (use sparingly, as PATCH is preferred)
func (t *TableClient) Put(sysID string, record map[string]interface{}) (map[string]interface{}, error) {
	var result core.Response
	err := t.client.RawRequest("PUT", buildTableRecordPath(t.name, sysID), record, nil, &result)
	if err != nil {
		return nil, err
	}
	replaced, ok := result.Result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result type for put: %T", result.Result)
	}
	return replaced, nil
}

// Delete removes a record using DELETE
func (t *TableClient) Delete(sysID string) error {
	return t.DeleteWithContext(context.Background(), sysID)
}

// DeleteWithContext removes a record using DELETE with context support
func (t *TableClient) DeleteWithContext(ctx context.Context, sysID string) error {
	return t.client.RawRequestWithContext(ctx, "DELETE", buildTableRecordPath(t.name, sysID), nil, nil, nil)
}

// Query returns a new QueryBuilder for this table
func (t *TableClient) Query() *query.QueryBuilder {
	return query.New()
}

// ListWithQuery executes a query using the query builder
func (t *TableClient) ListWithQuery(qb *query.QueryBuilder) ([]map[string]interface{}, error) {
	return t.ListWithQueryContext(context.Background(), qb)
}

// ListWithQueryContext executes a query using the query builder with context support
func (t *TableClient) ListWithQueryContext(ctx context.Context, qb *query.QueryBuilder) ([]map[string]interface{}, error) {
	params := qb.Build()
	return t.ListWithContext(ctx, params)
}

// Where creates a query builder with an initial condition
func (t *TableClient) Where(field string, operator query.Operator, value interface{}) *TableQuery {
	qb := query.New().Where(field, operator, value)
	return &TableQuery{
		table:   t,
		builder: qb,
	}
}

// Equals creates a query builder with an equality condition (convenience method)
func (t *TableClient) Equals(field string, value interface{}) *TableQuery {
	return t.Where(field, query.OpEquals, value)
}

// Contains creates a query builder with a contains condition (convenience method)
func (t *TableClient) Contains(field string, value interface{}) *TableQuery {
	return t.Where(field, query.OpContains, value)
}

// TableQuery wraps a query builder with table-specific methods
type TableQuery struct {
	table   *TableClient
	builder *query.QueryBuilder
}

// Where adds another condition (chainable)
func (tq *TableQuery) Where(field string, operator query.Operator, value interface{}) *TableQuery {
	tq.builder.Where(field, operator, value)
	return tq
}

// And adds an AND condition (chainable)
func (tq *TableQuery) And() *TableQuery {
	tq.builder.And()
	return tq
}

// Or adds an OR condition (chainable)
func (tq *TableQuery) Or() *TableQuery {
	tq.builder.Or()
	return tq
}

// Equals adds an equality condition (chainable)
func (tq *TableQuery) Equals(field string, value interface{}) *TableQuery {
	tq.builder.Equals(field, value)
	return tq
}

// Contains adds a contains condition (chainable)
func (tq *TableQuery) Contains(field string, value interface{}) *TableQuery {
	tq.builder.Contains(field, value)
	return tq
}

// OrderBy adds ordering (chainable)
func (tq *TableQuery) OrderBy(field string, direction query.OrderDirection) *TableQuery {
	tq.builder.OrderBy(field, direction)
	return tq
}

// OrderByAsc adds ascending order (chainable)
func (tq *TableQuery) OrderByAsc(field string) *TableQuery {
	tq.builder.OrderByAsc(field)
	return tq
}

// OrderByDesc adds descending order (chainable)
func (tq *TableQuery) OrderByDesc(field string) *TableQuery {
	tq.builder.OrderByDesc(field)
	return tq
}

// Fields specifies which fields to return (chainable)
func (tq *TableQuery) Fields(fields ...string) *TableQuery {
	tq.builder.Fields(fields...)
	return tq
}

// Limit sets the maximum number of records (chainable)
func (tq *TableQuery) Limit(limit int) *TableQuery {
	tq.builder.Limit(limit)
	return tq
}

// Offset sets the number of records to skip (chainable)
func (tq *TableQuery) Offset(offset int) *TableQuery {
	tq.builder.Offset(offset)
	return tq
}

// Execute runs the query and returns results
func (tq *TableQuery) Execute() ([]map[string]interface{}, error) {
	return tq.ExecuteWithContext(context.Background())
}

// ExecuteWithContext runs the query with context support and returns results
func (tq *TableQuery) ExecuteWithContext(ctx context.Context) ([]map[string]interface{}, error) {
	return tq.table.ListWithQueryContext(ctx, tq.builder)
}

// ExecuteOne runs the query and returns the first result
func (tq *TableQuery) ExecuteOne() (map[string]interface{}, error) {
	return tq.ExecuteOneWithContext(context.Background())
}

// ExecuteOneWithContext runs the query with context and returns the first result
func (tq *TableQuery) ExecuteOneWithContext(ctx context.Context) (map[string]interface{}, error) {
	results, err := tq.Limit(1).ExecuteWithContext(ctx)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("no records found")
	}
	return results[0], nil
}

// Count returns the number of records matching the query
func (tq *TableQuery) Count() (int, error) {
	return tq.CountWithContext(context.Background())
}

// CountWithContext returns the number of records matching the query with context support
func (tq *TableQuery) CountWithContext(ctx context.Context) (int, error) {
	params := map[string]string{
		"sysparm_count": "true",
	}
	if query := tq.builder.Clone().BuildQuery(); query != "" {
		params["sysparm_query"] = query
	}

	var result core.Response
	err := tq.table.client.RawRequestWithContext(ctx, "GET", buildTableStatsPath(tq.table.name), nil, params, &result)
	if err != nil {
		return 0, err
	}

	if resultData, ok := result.Result.(map[string]interface{}); ok {
		if stats, ok := resultData["stats"].(map[string]interface{}); ok {
			if count, ok := stats["count"]; ok {
				return parseCountValue(count), nil
			}
		}
		if count, ok := resultData["count"]; ok {
			return parseCountValue(count), nil
		}
	}

	return 0, fmt.Errorf("unexpected result type for count: %T", result.Result)
}

// GetBuilder returns the underlying query builder
func (tq *TableQuery) GetBuilder() *query.QueryBuilder {
	return tq.builder
}

// ListOptions for common sysparm params
type ListOptions struct {
	Query                    string                   // sysparm_query (use QueryBuilder.Build())
	Fields                   []string                 // sysparm_fields (comma-separated)
	Limit                    int                      // sysparm_limit
	Offset                   int                      // sysparm_offset
	DisplayValue             core.DisplayValueOptions // sysparm_display_value
	ExcludeReferenceLink     bool                     // sysparm_exclude_reference_link = true
	View                     string                   // sysparm_view
	NoCount                  bool                     // sysparm_no_count = true
	SuppressPaginationHeader bool                     // sysparm_suppress_pagination_header = true
	// Add more as needed (e.g., InputDisplayValue for POST)
}

// ListOpt performs List with type-safe options
func (t *TableClient) ListOpt(options ListOptions) ([]map[string]interface{}, error) {
	params := map[string]string{}
	if options.Query != "" {
		params["sysparm_query"] = options.Query
	}
	if len(options.Fields) > 0 {
		params["sysparm_fields"] = strings.Join(options.Fields, ",")
	}
	if options.Limit > 0 {
		params["sysparm_limit"] = fmt.Sprintf("%d", options.Limit)
	}
	if options.Offset > 0 {
		params["sysparm_offset"] = fmt.Sprintf("%d", options.Offset)
	}
	if options.DisplayValue != "" {
		params["sysparm_display_value"] = string(options.DisplayValue)
	}
	if options.ExcludeReferenceLink {
		params["sysparm_exclude_reference_link"] = "true"
	}
	if options.View != "" {
		params["sysparm_view"] = options.View
	}
	if options.NoCount {
		params["sysparm_no_count"] = "true"
	}
	if options.SuppressPaginationHeader {
		params["sysparm_suppress_pagination_header"] = "true"
	}
	return t.List(params)
}

// Paginate fetches all records by auto-paginating (calls ListOpt repeatedly)
func (t *TableClient) Paginate(options ListOptions, pageSize int) ([]map[string]interface{}, error) {
	if pageSize <= 0 {
		pageSize = 100 // Default page size
	}
	options.Limit = pageSize
	options.Offset = 0
	var allRecords []map[string]interface{}
	for {
		records, err := t.ListOpt(options)
		if err != nil {
			return nil, err
		}
		allRecords = append(allRecords, records...)
		if len(records) < pageSize {
			break // No more pages
		}
		options.Offset += pageSize
	}
	return allRecords, nil
}

// Helper functions
func getString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func getBool(v interface{}) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	if s, ok := v.(string); ok {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "true", "1", "yes":
			return true
		}
	}
	return false
}

func parseInt(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

// GetSchema retrieves table metadata via sys_dictionary (JSON)
func (t *TableClient) GetSchema() ([]core.ColumnMetadata, error) {
	dictClient := NewTableClient(t.client, "sys_dictionary")
	params := map[string]string{
		"sysparm_query":  fmt.Sprintf("name=%s^elementISNOTEMPTY", t.name),
		"sysparm_fields": "element,column_label,internal_type,max_length,mandatory,read_only,unique,reference,choice,calculated",
	}
	records, err := dictClient.List(params)
	if err != nil {
		return nil, err
	}
	var columns []core.ColumnMetadata
	for _, rec := range records {
		name := getString(rec["element"])
		if name == "" {
			continue
		}
		columns = append(columns, core.ColumnMetadata{
			Name:       name,
			Label:      getString(rec["column_label"]),
			Type:       getString(rec["internal_type"]),
			MaxLength:  parseInt(getString(rec["max_length"])),
			Mandatory:  getBool(rec["mandatory"]),
			ReadOnly:   getBool(rec["read_only"]),
			Unique:     getBool(rec["unique"]),
			Reference:  getString(rec["reference"]),
			Choice:     getBool(rec["choice"]),
			Calculated: getBool(rec["calculated"]),
		})
	}
	return columns, nil
}

// GetKeys retrieves sys_ids matching a query
func (t *TableClient) GetKeys(query string) ([]string, error) {
	params := map[string]string{
		"sysparm_fields": "sys_id",
	}
	if query != "" {
		params["sysparm_query"] = query
	}

	const pageSize = 1000
	var offset int
	var sysIDs []string

	for {
		params["sysparm_limit"] = strconv.Itoa(pageSize)
		params["sysparm_offset"] = strconv.Itoa(offset)

		var result core.Response
		err := t.client.RawRequest("GET", buildTablePath(t.name), nil, params, &result)
		if err != nil {
			return nil, err
		}

		records, ok := result.Result.([]interface{})
		if !ok {
			return nil, fmt.Errorf("unexpected result type for getKeys: %T", result.Result)
		}
		if len(records) == 0 {
			break
		}

		for _, record := range records {
			recordMap, ok := record.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("unexpected record type for getKeys: %T", record)
			}

			sysID, err := extractSysID(recordMap["sys_id"])
			if err != nil {
				return nil, err
			}
			if sysID != "" {
				sysIDs = append(sysIDs, sysID)
			}
		}

		if len(records) < pageSize {
			break
		}
		offset += pageSize
	}

	return sysIDs, nil
}

func extractSysID(value interface{}) (string, error) {
	switch id := value.(type) {
	case string:
		return id, nil
	case map[string]interface{}:
		if val, ok := id["value"].(string); ok && val != "" {
			return val, nil
		}
		if val, ok := id["sys_id"].(string); ok && val != "" {
			return val, nil
		}
		if val, ok := id["display_value"].(string); ok {
			return val, nil
		}
		return "", fmt.Errorf("unexpected sys_id map format: %+v", id)
	default:
		return "", fmt.Errorf("unexpected sys_id type: %T", id)
	}
}

func parseCountValue(value interface{}) int {
	switch v := value.(type) {
	case string:
		return parseInt(v)
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	default:
		return 0
	}
}
