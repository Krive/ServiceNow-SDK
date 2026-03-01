package importset

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"codeberg.org/Krive/ServiceNow-SDK/pkg/servicenow/core"
)

// ImportSetClient handles Import Set operations
type ImportSetClient struct {
	client *core.Client
}

// NewImportSetClient creates a new Import Set client
func NewImportSetClient(client *core.Client) *ImportSetClient {
	return &ImportSetClient{client: client}
}

// ImportRecord represents a single record to be imported
type ImportRecord map[string]interface{}

// ImportResponse represents the response from an import operation
type ImportResponse struct {
	ImportSet    string                   `json:"import_set"`
	StagingTable string                   `json:"staging_table"`
	Records      []map[string]interface{} `json:"records"`
}

// Insert inserts records into the specified import set table
func (i *ImportSetClient) Insert(tableName string, records []ImportRecord) (*ImportResponse, error) {
	return i.InsertWithContext(context.Background(), tableName, records)
}

// InsertWithContext inserts records into the specified import set table with context support
func (i *ImportSetClient) InsertWithContext(ctx context.Context, tableName string, records []ImportRecord) (*ImportResponse, error) {
	if len(records) == 0 {
		return nil, fmt.Errorf("no records provided for import")
	}

	// For single record, use direct insert
	if len(records) == 1 {
		normalizedRecord := normalizeImportRecord(records[0])
		var result core.Response
		err := i.insertRecordWithVersionFallback(ctx, tableName, normalizedRecord, &result)
		if err != nil {
			return nil, fmt.Errorf("failed to insert record: %w", err)
		}

		response := &ImportResponse{
			StagingTable: tableName,
		}

		if resultMap, ok := result.Result.(map[string]interface{}); ok {
			response.Records = []map[string]interface{}{resultMap}
		}

		return response, nil
	}

	// For multiple records, insert each one
	var allRecords []map[string]interface{}
	for _, record := range records {
		normalizedRecord := normalizeImportRecord(record)
		var result core.Response
		err := i.insertRecordWithVersionFallback(ctx, tableName, normalizedRecord, &result)
		if err != nil {
			return nil, fmt.Errorf("failed to insert record: %w", err)
		}

		if resultMap, ok := result.Result.(map[string]interface{}); ok {
			allRecords = append(allRecords, resultMap)
		}
	}

	return &ImportResponse{
		StagingTable: tableName,
		Records:      allRecords,
	}, nil
}

// GetImportSet retrieves information about an import set
func (i *ImportSetClient) GetImportSet(importSetSysID string) (map[string]interface{}, error) {
	return i.GetImportSetWithContext(context.Background(), importSetSysID)
}

// GetImportSetWithContext retrieves information about an import set with context support
func (i *ImportSetClient) GetImportSetWithContext(ctx context.Context, importSetSysID string) (map[string]interface{}, error) {
	importSetSysID = strings.TrimSpace(importSetSysID)
	if importSetSysID == "" {
		return nil, fmt.Errorf("import set sys_id cannot be empty")
	}

	var result core.Response
	err := i.client.RawRequestWithContext(ctx, "GET", buildImportSetLookupPath(importSetSysID), nil, nil, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to get import set: %w", err)
	}

	if resultMap, ok := result.Result.(map[string]interface{}); ok {
		return resultMap, nil
	}

	return nil, fmt.Errorf("unexpected result type: %T", result.Result)
}

func normalizeImportRecord(record ImportRecord) map[string]string {
	normalized := make(map[string]string, len(record))

	for key, value := range record {
		switch typed := value.(type) {
		case nil:
			normalized[key] = ""
		case string:
			normalized[key] = typed
		case []byte:
			normalized[key] = string(typed)
		default:
			// Preserve structure when possible for complex values.
			if payload, err := json.Marshal(typed); err == nil {
				normalized[key] = string(payload)
			} else {
				normalized[key] = fmt.Sprintf("%v", typed)
			}
		}
	}

	return normalized
}

// GetTransformResults retrieves the transform results for an import set
func (i *ImportSetClient) GetTransformResults(importSetSysID string) ([]map[string]interface{}, error) {
	return i.GetTransformResultsWithContext(context.Background(), importSetSysID)
}

// GetTransformResultsWithContext retrieves the transform results for an import set with context support
func (i *ImportSetClient) GetTransformResultsWithContext(ctx context.Context, importSetSysID string) ([]map[string]interface{}, error) {
	importSetSysID = strings.TrimSpace(importSetSysID)
	if importSetSysID == "" {
		return nil, fmt.Errorf("import set sys_id cannot be empty")
	}

	params := map[string]string{
		"sysparm_query": fmt.Sprintf("import_set=%s", sanitizeEncodedQueryValue(importSetSysID)),
	}

	var result core.Response
	err := i.client.RawRequestWithContext(ctx, "GET", "/table/sys_transform_entry", nil, params, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to get transform results: %w", err)
	}

	if resultSlice, ok := result.Result.([]interface{}); ok {
		var transformResults []map[string]interface{}
		for _, item := range resultSlice {
			if itemMap, ok := item.(map[string]interface{}); ok {
				transformResults = append(transformResults, itemMap)
			}
		}
		return transformResults, nil
	}

	return nil, fmt.Errorf("unexpected result type: %T", result.Result)
}

func buildImportSetLookupPath(importSetSysID string) string {
	return fmt.Sprintf("/table/sys_import_set/%s", url.PathEscape(importSetSysID))
}

func buildImportInsertPath(tableName string) string {
	return fmt.Sprintf("/import/%s", url.PathEscape(strings.TrimSpace(tableName)))
}

func buildImportInsertV1Path(tableName string) string {
	return fmt.Sprintf("/v1/import/%s", url.PathEscape(strings.TrimSpace(tableName)))
}

func (i *ImportSetClient) insertRecordWithVersionFallback(
	ctx context.Context,
	tableName string,
	record map[string]string,
	result interface{},
) error {
	path := buildImportInsertPath(tableName)
	err := i.client.RawRequestWithContext(ctx, "POST", path, record, nil, result)
	if !shouldRetryWithV1ImportPath(err) {
		return err
	}

	return i.client.RawRequestWithContext(ctx, "POST", buildImportInsertV1Path(tableName), record, nil, result)
}

func shouldRetryWithV1ImportPath(err error) bool {
	if err == nil {
		return false
	}

	snErr, ok := core.IsServiceNowError(err)
	if !ok {
		return false
	}

	return snErr.StatusCode == 404 || snErr.StatusCode == 405
}

func sanitizeEncodedQueryValue(value string) string {
	cleaned := strings.ReplaceAll(value, "^", " ")
	cleaned = strings.ReplaceAll(cleaned, "\n", " ")
	cleaned = strings.ReplaceAll(cleaned, "\r", " ")
	return cleaned
}
