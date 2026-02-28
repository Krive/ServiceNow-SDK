package batch

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Krive/ServiceNow-SDK/pkg/servicenow/core"
)

// BatchClient handles ServiceNow Batch API operations
type BatchClient struct {
	client *core.Client
}

// NewBatchClient creates a new batch client
func NewBatchClient(client *core.Client) *BatchClient {
	return &BatchClient{
		client: client,
	}
}

// HTTPMethod represents supported HTTP methods for batch requests
type HTTPMethod string

const (
	MethodGET    HTTPMethod = "GET"
	MethodPOST   HTTPMethod = "POST"
	MethodPATCH  HTTPMethod = "PATCH"
	MethodPUT    HTTPMethod = "PUT"
	MethodDELETE HTTPMethod = "DELETE"
)

// BatchRequest represents the entire batch request payload
type BatchRequest struct {
	BatchRequestID  string       `json:"batch_request_id"`
	EnforceOrder    bool         `json:"enforce_order,omitempty"`
	RestRequests    []RestRequest `json:"rest_requests"`
}

// RestRequest represents an individual request within a batch
type RestRequest struct {
	ID                      string   `json:"id"`
	URL                     string   `json:"url"`
	Method                  HTTPMethod `json:"method"`
	Headers                 []Header `json:"headers,omitempty"`
	Body                    string   `json:"body,omitempty"` // Base64 encoded
	ExcludeResponseHeaders  bool     `json:"exclude_response_headers,omitempty"`
}

// Header represents a HTTP header
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// BatchResponse represents the response from a batch request
type BatchResponse struct {
	BatchRequestID      string            `json:"batch_request_id"`
	ServicedRequests    []ServicedRequest `json:"serviced_requests"`
	UnservicedRequests  []UnservicedRequest `json:"unserviced_requests"`
}

// ServicedRequest represents a successfully processed request
type ServicedRequest struct {
	ID            string `json:"id"`
	StatusCode    int    `json:"status_code"`
	StatusText    string `json:"status_text"`
	Body          string `json:"body"` // Base64 encoded
	ExecutionTime int    `json:"execution_time"`
}

// UnservicedRequest represents a failed request
type UnservicedRequest struct {
	ID          string `json:"id"`
	StatusCode  int    `json:"status_code"`
	StatusText  string `json:"status_text"`
	ErrorDetail string `json:"error_detail,omitempty"`
}

// BatchBuilder provides a fluent interface for building batch requests
type BatchBuilder struct {
	client      *BatchClient
	requestID   string
	enforceOrder bool
	requests    []RestRequest
}

// NewBatch creates a new batch builder
func (bc *BatchClient) NewBatch() *BatchBuilder {
	return &BatchBuilder{
		client:       bc,
		requestID:    generateBatchID(),
		enforceOrder: false,
		requests:     make([]RestRequest, 0),
	}
}

// WithRequestID sets a custom batch request ID
func (bb *BatchBuilder) WithRequestID(id string) *BatchBuilder {
	bb.requestID = id
	return bb
}

// WithEnforceOrder enables sequential execution of requests
func (bb *BatchBuilder) WithEnforceOrder(enforce bool) *BatchBuilder {
	bb.enforceOrder = enforce
	return bb
}

// Get adds a GET request to the batch
func (bb *BatchBuilder) Get(id, url string) *BatchBuilder {
	request := RestRequest{
		ID:                     id,
		URL:                    url,
		Method:                MethodGET,
		ExcludeResponseHeaders: true,
		Headers: []Header{
			{Name: "Accept", Value: "application/json"},
		},
	}
	bb.requests = append(bb.requests, request)
	return bb
}

// Create adds a POST request to the batch
func (bb *BatchBuilder) Create(id, tableName string, data map[string]interface{}) *BatchBuilder {
	body, _ := json.Marshal(data)
	encodedBody := base64.StdEncoding.EncodeToString(body)
	
	request := RestRequest{
		ID:                     id,
		URL:                    fmt.Sprintf("/api/now/table/%s", tableName),
		Method:                MethodPOST,
		ExcludeResponseHeaders: true,
		Headers: []Header{
			{Name: "Content-Type", Value: "application/json"},
			{Name: "Accept", Value: "application/json"},
		},
		Body: encodedBody,
	}
	bb.requests = append(bb.requests, request)
	return bb
}

// Update adds a PATCH request to the batch
func (bb *BatchBuilder) Update(id, tableName, sysID string, data map[string]interface{}) *BatchBuilder {
	body, _ := json.Marshal(data)
	encodedBody := base64.StdEncoding.EncodeToString(body)
	
	request := RestRequest{
		ID:                     id,
		URL:                    fmt.Sprintf("/api/now/table/%s/%s", tableName, sysID),
		Method:                MethodPATCH,
		ExcludeResponseHeaders: true,
		Headers: []Header{
			{Name: "Content-Type", Value: "application/json"},
			{Name: "Accept", Value: "application/json"},
		},
		Body: encodedBody,
	}
	bb.requests = append(bb.requests, request)
	return bb
}

// Replace adds a PUT request to the batch
func (bb *BatchBuilder) Replace(id, tableName, sysID string, data map[string]interface{}) *BatchBuilder {
	body, _ := json.Marshal(data)
	encodedBody := base64.StdEncoding.EncodeToString(body)
	
	request := RestRequest{
		ID:                     id,
		URL:                    fmt.Sprintf("/api/now/table/%s/%s", tableName, sysID),
		Method:                MethodPUT,
		ExcludeResponseHeaders: true,
		Headers: []Header{
			{Name: "Content-Type", Value: "application/json"},
			{Name: "Accept", Value: "application/json"},
		},
		Body: encodedBody,
	}
	bb.requests = append(bb.requests, request)
	return bb
}

// Delete adds a DELETE request to the batch
func (bb *BatchBuilder) Delete(id, tableName, sysID string) *BatchBuilder {
	request := RestRequest{
		ID:                     id,
		URL:                    fmt.Sprintf("/api/now/table/%s/%s", tableName, sysID),
		Method:                MethodDELETE,
		ExcludeResponseHeaders: true,
	}
	bb.requests = append(bb.requests, request)
	return bb
}

// AddCustomRequest adds a custom request to the batch
func (bb *BatchBuilder) AddCustomRequest(req RestRequest) *BatchBuilder {
	bb.requests = append(bb.requests, req)
	return bb
}

// Execute executes the batch request
func (bb *BatchBuilder) Execute() (*BatchResult, error) {
	return bb.ExecuteWithContext(context.Background())
}

// ExecuteWithContext executes the batch request with context support
func (bb *BatchBuilder) ExecuteWithContext(ctx context.Context) (*BatchResult, error) {
	if len(bb.requests) == 0 {
		return nil, fmt.Errorf("batch request cannot be empty")
	}

	batchRequest := BatchRequest{
		BatchRequestID: bb.requestID,
		EnforceOrder:   bb.enforceOrder,
		RestRequests:   bb.requests,
	}

	var response BatchResponse
	err := bb.client.client.RawRequestWithContext(ctx, "POST", "/batch", batchRequest, nil, &response)
	if err != nil {
		return nil, fmt.Errorf("batch request failed: %w", err)
	}

	return parseBatchResponse(&response)
}

// BatchResult provides a convenient interface for accessing batch results
type BatchResult struct {
	BatchRequestID     string
	TotalRequests      int
	SuccessfulRequests int
	FailedRequests     int
	Results            map[string]*RequestResult
	Errors             map[string]*RequestError
}

// RequestResult represents a successful request result
type RequestResult struct {
	ID            string
	StatusCode    int
	StatusText    string
	Data          map[string]interface{} // Decoded JSON response
	ExecutionTime time.Duration
}

// RequestError represents a failed request
type RequestError struct {
	ID          string
	StatusCode  int
	StatusText  string
	ErrorDetail string
}

// GetResult returns the result for a specific request ID
func (br *BatchResult) GetResult(id string) (*RequestResult, bool) {
	result, exists := br.Results[id]
	return result, exists
}

// GetError returns the error for a specific request ID
func (br *BatchResult) GetError(id string) (*RequestError, bool) {
	err, exists := br.Errors[id]
	return err, exists
}

// IsSuccess returns true if the request was successful
func (br *BatchResult) IsSuccess(id string) bool {
	_, exists := br.Results[id]
	return exists
}

// GetAllSuccessful returns all successful results
func (br *BatchResult) GetAllSuccessful() map[string]*RequestResult {
	return br.Results
}

// GetAllErrors returns all errors
func (br *BatchResult) GetAllErrors() map[string]*RequestError {
	return br.Errors
}

// HasErrors returns true if any requests failed
func (br *BatchResult) HasErrors() bool {
	return len(br.Errors) > 0
}

// parseBatchResponse parses the ServiceNow batch response into a BatchResult
func parseBatchResponse(response *BatchResponse) (*BatchResult, error) {
	result := &BatchResult{
		BatchRequestID:     response.BatchRequestID,
		TotalRequests:      len(response.ServicedRequests) + len(response.UnservicedRequests),
		SuccessfulRequests: len(response.ServicedRequests),
		FailedRequests:     len(response.UnservicedRequests),
		Results:            make(map[string]*RequestResult),
		Errors:             make(map[string]*RequestError),
	}

	// Process successful requests
	for _, servicedReq := range response.ServicedRequests {
		reqResult := &RequestResult{
			ID:            servicedReq.ID,
			StatusCode:    servicedReq.StatusCode,
			StatusText:    servicedReq.StatusText,
			ExecutionTime: time.Duration(servicedReq.ExecutionTime) * time.Millisecond,
		}

		// Decode response body if present
		if servicedReq.Body != "" {
			bodyBytes, err := base64.StdEncoding.DecodeString(servicedReq.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to decode response body for request %s: %w", servicedReq.ID, err)
			}

			// Try to parse as JSON
			var data map[string]interface{}
			if err := json.Unmarshal(bodyBytes, &data); err == nil {
				reqResult.Data = data
			}
		}

		result.Results[servicedReq.ID] = reqResult
	}

	// Process failed requests
	for _, unservicedReq := range response.UnservicedRequests {
		reqError := &RequestError{
			ID:          unservicedReq.ID,
			StatusCode:  unservicedReq.StatusCode,
			StatusText:  unservicedReq.StatusText,
			ErrorDetail: unservicedReq.ErrorDetail,
		}

		result.Errors[unservicedReq.ID] = reqError
	}

	return result, nil
}

// generateBatchID generates a unique batch request ID
func generateBatchID() string {
	return fmt.Sprintf("batch_%d", time.Now().UnixNano())
}

// Convenience methods for common batch operations

// CreateMultiple creates multiple records in a single batch
func (bc *BatchClient) CreateMultiple(tableName string, records []map[string]interface{}) (*BatchResult, error) {
	return bc.CreateMultipleWithContext(context.Background(), tableName, records)
}

// CreateMultipleWithContext creates multiple records with context support
func (bc *BatchClient) CreateMultipleWithContext(ctx context.Context, tableName string, records []map[string]interface{}) (*BatchResult, error) {
	batch := bc.NewBatch()
	
	for i, record := range records {
		id := fmt.Sprintf("create_%d", i+1)
		batch.Create(id, tableName, record)
	}
	
	return batch.ExecuteWithContext(ctx)
}

// UpdateMultiple updates multiple records in a single batch
func (bc *BatchClient) UpdateMultiple(tableName string, updates map[string]map[string]interface{}) (*BatchResult, error) {
	return bc.UpdateMultipleWithContext(context.Background(), tableName, updates)
}

// UpdateMultipleWithContext updates multiple records with context support
func (bc *BatchClient) UpdateMultipleWithContext(ctx context.Context, tableName string, updates map[string]map[string]interface{}) (*BatchResult, error) {
	batch := bc.NewBatch()
	
	i := 1
	for sysID, data := range updates {
		id := fmt.Sprintf("update_%d", i)
		batch.Update(id, tableName, sysID, data)
		i++
	}
	
	return batch.ExecuteWithContext(ctx)
}

// DeleteMultiple deletes multiple records in a single batch
func (bc *BatchClient) DeleteMultiple(tableName string, sysIDs []string) (*BatchResult, error) {
	return bc.DeleteMultipleWithContext(context.Background(), tableName, sysIDs)
}

// DeleteMultipleWithContext deletes multiple records with context support
func (bc *BatchClient) DeleteMultipleWithContext(ctx context.Context, tableName string, sysIDs []string) (*BatchResult, error) {
	batch := bc.NewBatch()
	
	for i, sysID := range sysIDs {
		id := fmt.Sprintf("delete_%d", i+1)
		batch.Delete(id, tableName, sysID)
	}
	
	return batch.ExecuteWithContext(ctx)
}

// GetMultiple retrieves multiple records in a single batch
func (bc *BatchClient) GetMultiple(tableName string, sysIDs []string) (*BatchResult, error) {
	return bc.GetMultipleWithContext(context.Background(), tableName, sysIDs)
}

// GetMultipleWithContext retrieves multiple records with context support
func (bc *BatchClient) GetMultipleWithContext(ctx context.Context, tableName string, sysIDs []string) (*BatchResult, error) {
	batch := bc.NewBatch()
	
	for i, sysID := range sysIDs {
		id := fmt.Sprintf("get_%d", i+1)
		url := fmt.Sprintf("/api/now/table/%s/%s", tableName, sysID)
		batch.Get(id, url)
	}
	
	return batch.ExecuteWithContext(ctx)
}

// MixedOperations allows combining different operations in a single batch
type MixedOperations struct {
	Creates []CreateOperation
	Updates []UpdateOperation
	Deletes []DeleteOperation
	Gets    []GetOperation
}

// CreateOperation represents a create operation
type CreateOperation struct {
	ID        string
	TableName string
	Data      map[string]interface{}
}

// UpdateOperation represents an update operation
type UpdateOperation struct {
	ID        string
	TableName string
	SysID     string
	Data      map[string]interface{}
}

// DeleteOperation represents a delete operation
type DeleteOperation struct {
	ID        string
	TableName string
	SysID     string
}

// GetOperation represents a get operation
type GetOperation struct {
	ID        string
	TableName string
	SysID     string
}

// ExecuteMixed executes mixed operations in a single batch
func (bc *BatchClient) ExecuteMixed(operations MixedOperations) (*BatchResult, error) {
	return bc.ExecuteMixedWithContext(context.Background(), operations)
}

// ExecuteMixedWithContext executes mixed operations with context support
func (bc *BatchClient) ExecuteMixedWithContext(ctx context.Context, operations MixedOperations) (*BatchResult, error) {
	batch := bc.NewBatch()
	
	// Add create operations
	for _, op := range operations.Creates {
		batch.Create(op.ID, op.TableName, op.Data)
	}
	
	// Add update operations
	for _, op := range operations.Updates {
		batch.Update(op.ID, op.TableName, op.SysID, op.Data)
	}
	
	// Add delete operations
	for _, op := range operations.Deletes {
		batch.Delete(op.ID, op.TableName, op.SysID)
	}
	
	// Add get operations
	for _, op := range operations.Gets {
		url := fmt.Sprintf("/api/now/table/%s/%s", op.TableName, op.SysID)
		batch.Get(op.ID, url)
	}
	
	return batch.ExecuteWithContext(ctx)
}

// Helper method to extract record data from batch result
func ExtractRecordData(result *RequestResult) (map[string]interface{}, error) {
	if result.Data == nil {
		return nil, fmt.Errorf("no data in result")
	}
	
	// ServiceNow typically wraps single records in a "result" field
	if resultField, exists := result.Data["result"]; exists {
		if record, ok := resultField.(map[string]interface{}); ok {
			return record, nil
		}
	}
	
	// If no "result" wrapper, return the data as-is
	return result.Data, nil
}

// Helper method to extract multiple records from batch result
func ExtractMultipleRecords(results map[string]*RequestResult) ([]map[string]interface{}, error) {
	var records []map[string]interface{}
	
	for _, result := range results {
		record, err := ExtractRecordData(result)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	
	return records, nil
}