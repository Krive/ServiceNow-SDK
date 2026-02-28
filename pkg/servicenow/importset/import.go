package importset

import (
	"context"
	"fmt"

	"github.com/Krive/ServiceNow-SDK/pkg/servicenow/core"
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
	ImportSet string                   `json:"import_set"`
	StagingTable string               `json:"staging_table"`
	Records   []map[string]interface{} `json:"records"`
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
		var result core.Response
		err := i.client.RawRequestWithContext(ctx, "POST", fmt.Sprintf("/import/%s", tableName), records[0], nil, &result)
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
		var result core.Response
		err := i.client.RawRequestWithContext(ctx, "POST", fmt.Sprintf("/import/%s", tableName), record, nil, &result)
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
	var result core.Response
	err := i.client.RawRequestWithContext(ctx, "GET", fmt.Sprintf("/import/sys_import_set/%s", importSetSysID), nil, nil, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to get import set: %w", err)
	}

	if resultMap, ok := result.Result.(map[string]interface{}); ok {
		return resultMap, nil
	}

	return nil, fmt.Errorf("unexpected result type: %T", result.Result)
}

// GetTransformResults retrieves the transform results for an import set
func (i *ImportSetClient) GetTransformResults(importSetSysID string) ([]map[string]interface{}, error) {
	return i.GetTransformResultsWithContext(context.Background(), importSetSysID)
}

// GetTransformResultsWithContext retrieves the transform results for an import set with context support
func (i *ImportSetClient) GetTransformResultsWithContext(ctx context.Context, importSetSysID string) ([]map[string]interface{}, error) {
	params := map[string]string{
		"sysparm_query": fmt.Sprintf("import_set=%s", importSetSysID),
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