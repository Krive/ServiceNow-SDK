package catalog

import (
	"context"
	"fmt"
	"time"

	"github.com/Krive/ServiceNow-SDK/pkg/servicenow/core"
)

// OrderResult represents the result of submitting an order
type OrderResult struct {
	Success       bool          `json:"success"`
	RequestNumber string        `json:"request_number"`
	RequestSysID  string        `json:"request_sys_id"`
	RequestItems  []RequestItem `json:"request_items"`
	Message       string        `json:"message,omitempty"`
	Error         string        `json:"error,omitempty"`
}

// Request represents a ServiceNow catalog request (sc_request)
type Request struct {
	SysID             string    `json:"sys_id"`
	Number            string    `json:"number"`
	State             string    `json:"state"`
	Stage             string    `json:"stage"`
	RequestedBy       string    `json:"requested_by"`
	RequestedFor      string    `json:"requested_for"`
	OpenedBy          string    `json:"opened_by"`
	OpenedAt          time.Time `json:"opened_at"`
	Description       string    `json:"description"`
	ShortDescription  string    `json:"short_description"`
	Justification     string    `json:"justification"`
	SpecialInstructions string  `json:"special_instructions"`
	DeliveryAddress   string    `json:"delivery_address"`
	RequestedDate     time.Time `json:"requested_date"`
	DueDate           time.Time `json:"due_date"`
	Price             string    `json:"price"`
	Priority          string    `json:"priority"`
	Urgency           string    `json:"urgency"`
	Impact            string    `json:"impact"`
	ApprovalState     string    `json:"approval"`
	RequestItems      []RequestItem `json:"request_items,omitempty"`
}

// RequestItem represents a ServiceNow request item (sc_req_item)
type RequestItem struct {
	SysID                 string                 `json:"sys_id"`
	Number                string                 `json:"number"`
	State                 string                 `json:"state"`
	Stage                 string                 `json:"stage"`
	RequestSysID          string                 `json:"request"`
	CatalogItemSysID      string                 `json:"cat_item"`
	Quantity              int                    `json:"quantity"`
	Price                 string                 `json:"price"`
	RecurringPrice        string                 `json:"recurring_price"`
	RequestedBy           string                 `json:"requested_by"`
	RequestedFor          string                 `json:"requested_for"`
	OpenedBy              string                 `json:"opened_by"`
	OpenedAt              time.Time              `json:"opened_at"`
	DueDate               time.Time              `json:"due_date"`
	Variables             map[string]interface{} `json:"variables,omitempty"`
	CatalogItem           *CatalogItem           `json:"catalog_item,omitempty"`
	Tasks                 []CatalogTask          `json:"tasks,omitempty"`
	ApprovalState         string                 `json:"approval"`
	FulfillmentGroup      string                 `json:"assignment_group"`
	AssignedTo            string                 `json:"assigned_to"`
	BusinessService       string                 `json:"business_service"`
	ConfigurationItem     string                 `json:"cmdb_ci"`
	DeliveryAddress       string                 `json:"delivery_address"`
	SpecialInstructions   string                 `json:"special_instructions"`
}

// CatalogTask represents a ServiceNow catalog task (sc_task)
type CatalogTask struct {
	SysID            string    `json:"sys_id"`
	Number           string    `json:"number"`
	State            string    `json:"state"`
	RequestItemSysID string    `json:"request_item"`
	ShortDescription string    `json:"short_description"`
	Description      string    `json:"description"`
	AssignedTo       string    `json:"assigned_to"`
	AssignmentGroup  string    `json:"assignment_group"`
	OpenedBy         string    `json:"opened_by"`
	OpenedAt         time.Time `json:"opened_at"`
	DueDate          time.Time `json:"due_date"`
	ClosedAt         time.Time `json:"closed_at"`
	ClosedBy         string    `json:"closed_by"`
	Priority         string    `json:"priority"`
	WorkNotes        string    `json:"work_notes"`
	CloseNotes       string    `json:"close_notes"`
}

// RequestTracker provides methods for tracking catalog requests
type RequestTracker struct {
	client *CatalogClient
}

// NewRequestTracker creates a new request tracker
func (cc *CatalogClient) NewRequestTracker() *RequestTracker {
	return &RequestTracker{
		client: cc,
	}
}

// GetRequest returns a catalog request by number or sys_id
func (rt *RequestTracker) GetRequest(identifier string) (*Request, error) {
	return rt.GetRequestWithContext(context.Background(), identifier)
}

// GetRequestWithContext returns a catalog request with context support
func (rt *RequestTracker) GetRequestWithContext(ctx context.Context, identifier string) (*Request, error) {
	// Determine if identifier is sys_id or number
	var query string
	if len(identifier) == 32 && isHexString(identifier) {
		query = fmt.Sprintf("sys_id=%s", identifier)
	} else {
		query = fmt.Sprintf("number=%s", identifier)
	}

	params := map[string]string{
		"sysparm_query": query,
		"sysparm_limit": "1",
	}

	var response core.Response
	err := rt.client.client.RawRequestWithContext(ctx, "GET", "/table/sc_request", nil, params, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to get request: %w", err)
	}

	results, ok := response.Result.([]interface{})
	if !ok || len(results) == 0 {
		return nil, fmt.Errorf("request not found: %s", identifier)
	}

	requestData, ok := results[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response format for request")
	}

	request := rt.parseRequest(requestData)
	return &request, nil
}

// GetRequestWithItems returns a request with its request items
func (rt *RequestTracker) GetRequestWithItems(identifier string) (*Request, error) {
	return rt.GetRequestWithItemsWithContext(context.Background(), identifier)
}

// GetRequestWithItemsWithContext returns a request with items and context support
func (rt *RequestTracker) GetRequestWithItemsWithContext(ctx context.Context, identifier string) (*Request, error) {
	// First get the request
	request, err := rt.GetRequestWithContext(ctx, identifier)
	if err != nil {
		return nil, err
	}

	// Then get its request items
	items, err := rt.GetRequestItemsWithContext(ctx, request.Number)
	if err != nil {
		return nil, fmt.Errorf("failed to get request items: %w", err)
	}

	request.RequestItems = items
	return request, nil
}

// GetRequestItems returns request items for a request
func (rt *RequestTracker) GetRequestItems(requestIdentifier string) ([]RequestItem, error) {
	return rt.GetRequestItemsWithContext(context.Background(), requestIdentifier)
}

// GetRequestItemsWithContext returns request items with context support
func (rt *RequestTracker) GetRequestItemsWithContext(ctx context.Context, requestIdentifier string) ([]RequestItem, error) {
	var query string
	if len(requestIdentifier) == 32 && isHexString(requestIdentifier) {
		query = fmt.Sprintf("request=%s", requestIdentifier)
	} else {
		query = fmt.Sprintf("request.number=%s", requestIdentifier)
	}

	params := map[string]string{
		"sysparm_query": query,
		"sysparm_orderby": "number",
	}

	var response core.Response
	err := rt.client.client.RawRequestWithContext(ctx, "GET", "/table/sc_req_item", nil, params, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to get request items: %w", err)
	}

	results, ok := response.Result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response format for request items")
	}

	items := make([]RequestItem, 0, len(results))
	for _, result := range results {
		itemData, ok := result.(map[string]interface{})
		if !ok {
			continue
		}

		item := rt.parseRequestItem(itemData)
		items = append(items, item)
	}

	return items, nil
}

// GetRequestItem returns a specific request item
func (rt *RequestTracker) GetRequestItem(identifier string) (*RequestItem, error) {
	return rt.GetRequestItemWithContext(context.Background(), identifier)
}

// GetRequestItemWithContext returns a request item with context support
func (rt *RequestTracker) GetRequestItemWithContext(ctx context.Context, identifier string) (*RequestItem, error) {
	var query string
	if len(identifier) == 32 && isHexString(identifier) {
		query = fmt.Sprintf("sys_id=%s", identifier)
	} else {
		query = fmt.Sprintf("number=%s", identifier)
	}

	params := map[string]string{
		"sysparm_query": query,
		"sysparm_limit": "1",
	}

	var response core.Response
	err := rt.client.client.RawRequestWithContext(ctx, "GET", "/table/sc_req_item", nil, params, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to get request item: %w", err)
	}

	results, ok := response.Result.([]interface{})
	if !ok || len(results) == 0 {
		return nil, fmt.Errorf("request item not found: %s", identifier)
	}

	itemData, ok := results[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response format for request item")
	}

	item := rt.parseRequestItem(itemData)
	return &item, nil
}

// GetRequestItemWithTasks returns a request item with its tasks
func (rt *RequestTracker) GetRequestItemWithTasks(identifier string) (*RequestItem, error) {
	return rt.GetRequestItemWithTasksWithContext(context.Background(), identifier)
}

// GetRequestItemWithTasksWithContext returns request item with tasks and context support
func (rt *RequestTracker) GetRequestItemWithTasksWithContext(ctx context.Context, identifier string) (*RequestItem, error) {
	// First get the request item
	item, err := rt.GetRequestItemWithContext(ctx, identifier)
	if err != nil {
		return nil, err
	}

	// Then get its tasks
	tasks, err := rt.GetRequestItemTasksWithContext(ctx, item.Number)
	if err != nil {
		return nil, fmt.Errorf("failed to get request item tasks: %w", err)
	}

	item.Tasks = tasks
	return item, nil
}

// GetRequestItemTasks returns tasks for a request item
func (rt *RequestTracker) GetRequestItemTasks(requestItemIdentifier string) ([]CatalogTask, error) {
	return rt.GetRequestItemTasksWithContext(context.Background(), requestItemIdentifier)
}

// GetRequestItemTasksWithContext returns tasks with context support
func (rt *RequestTracker) GetRequestItemTasksWithContext(ctx context.Context, requestItemIdentifier string) ([]CatalogTask, error) {
	var query string
	if len(requestItemIdentifier) == 32 && isHexString(requestItemIdentifier) {
		query = fmt.Sprintf("request_item=%s", requestItemIdentifier)
	} else {
		query = fmt.Sprintf("request_item.number=%s", requestItemIdentifier)
	}

	params := map[string]string{
		"sysparm_query": query,
		"sysparm_orderby": "number",
	}

	var response core.Response
	err := rt.client.client.RawRequestWithContext(ctx, "GET", "/table/sc_task", nil, params, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to get catalog tasks: %w", err)
	}

	results, ok := response.Result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response format for catalog tasks")
	}

	tasks := make([]CatalogTask, 0, len(results))
	for _, result := range results {
		taskData, ok := result.(map[string]interface{})
		if !ok {
			continue
		}

		task := rt.parseCatalogTask(taskData)
		tasks = append(tasks, task)
	}

	return tasks, nil
}

// GetMyRequests returns requests for the current user
func (rt *RequestTracker) GetMyRequests(limit int) ([]Request, error) {
	return rt.GetMyRequestsWithContext(context.Background(), limit)
}

// GetMyRequestsWithContext returns user's requests with context support
func (rt *RequestTracker) GetMyRequestsWithContext(ctx context.Context, limit int) ([]Request, error) {
	params := map[string]string{
		"sysparm_query": "requested_by=javascript:gs.getUserID()",
		"sysparm_orderby": "sys_created_on DESC",
	}

	if limit > 0 {
		params["sysparm_limit"] = fmt.Sprintf("%d", limit)
	}

	var response core.Response
	err := rt.client.client.RawRequestWithContext(ctx, "GET", "/table/sc_request", nil, params, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to get user requests: %w", err)
	}

	results, ok := response.Result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response format for requests")
	}

	requests := make([]Request, 0, len(results))
	for _, result := range results {
		requestData, ok := result.(map[string]interface{})
		if !ok {
			continue
		}

		request := rt.parseRequest(requestData)
		requests = append(requests, request)
	}

	return requests, nil
}

// GetRequestsByState returns requests in a specific state
func (rt *RequestTracker) GetRequestsByState(state string) ([]Request, error) {
	return rt.GetRequestsByStateWithContext(context.Background(), state)
}

// GetRequestsByStateWithContext returns requests by state with context support
func (rt *RequestTracker) GetRequestsByStateWithContext(ctx context.Context, state string) ([]Request, error) {
	params := map[string]string{
		"sysparm_query": fmt.Sprintf("state=%s", state),
		"sysparm_orderby": "sys_created_on DESC",
	}

	var response core.Response
	err := rt.client.client.RawRequestWithContext(ctx, "GET", "/table/sc_request", nil, params, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to get requests by state: %w", err)
	}

	results, ok := response.Result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response format for requests")
	}

	requests := make([]Request, 0, len(results))
	for _, result := range results {
		requestData, ok := result.(map[string]interface{})
		if !ok {
			continue
		}

		request := rt.parseRequest(requestData)
		requests = append(requests, request)
	}

	return requests, nil
}

// TrackRequestProgress tracks the progress of a request over time
func (rt *RequestTracker) TrackRequestProgress(requestIdentifier string, callback func(*Request, []RequestItem)) error {
	return rt.TrackRequestProgressWithContext(context.Background(), requestIdentifier, callback)
}

// TrackRequestProgressWithContext tracks request progress with context support
func (rt *RequestTracker) TrackRequestProgressWithContext(ctx context.Context, requestIdentifier string, callback func(*Request, []RequestItem)) error {
	// This is a simple polling implementation
	// In a real implementation, you might want to use ServiceNow's event system or websockets
	
	ticker := time.NewTicker(30 * time.Second) // Poll every 30 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			request, err := rt.GetRequestWithContext(ctx, requestIdentifier)
			if err != nil {
				return fmt.Errorf("failed to track request progress: %w", err)
			}

			items, err := rt.GetRequestItemsWithContext(ctx, request.SysID)
			if err != nil {
				return fmt.Errorf("failed to get request items for tracking: %w", err)
			}

			callback(request, items)

			// Stop tracking if request is closed
			if request.State == "closed_complete" || request.State == "closed_cancelled" {
				return nil
			}
		}
	}
}

// Helper parsing functions

func (rt *RequestTracker) parseRequest(data map[string]interface{}) Request {
	return Request{
		SysID:               getString(data["sys_id"]),
		Number:              getString(data["number"]),
		State:               getString(data["state"]),
		Stage:               getString(data["stage"]),
		RequestedBy:         getString(data["requested_by"]),
		RequestedFor:        getString(data["requested_for"]),
		OpenedBy:            getString(data["opened_by"]),
		OpenedAt:            parseTime(getString(data["opened_at"])),
		Description:         getString(data["description"]),
		ShortDescription:    getString(data["short_description"]),
		Justification:       getString(data["justification"]),
		SpecialInstructions: getString(data["special_instructions"]),
		DeliveryAddress:     getString(data["delivery_address"]),
		RequestedDate:       parseTime(getString(data["requested_date"])),
		DueDate:             parseTime(getString(data["due_date"])),
		Price:               getString(data["price"]),
		Priority:            getString(data["priority"]),
		Urgency:             getString(data["urgency"]),
		Impact:              getString(data["impact"]),
		ApprovalState:       getString(data["approval"]),
	}
}

func (rt *RequestTracker) parseRequestItem(data map[string]interface{}) RequestItem {
	return RequestItem{
		SysID:                 getString(data["sys_id"]),
		Number:                getString(data["number"]),
		State:                 getString(data["state"]),
		Stage:                 getString(data["stage"]),
		RequestSysID:          getString(data["request"]),
		CatalogItemSysID:      getString(data["cat_item"]),
		Quantity:              getInt(data["quantity"]),
		Price:                 getString(data["price"]),
		RecurringPrice:        getString(data["recurring_price"]),
		RequestedBy:           getString(data["requested_by"]),
		RequestedFor:          getString(data["requested_for"]),
		OpenedBy:              getString(data["opened_by"]),
		OpenedAt:              parseTime(getString(data["opened_at"])),
		DueDate:               parseTime(getString(data["due_date"])),
		ApprovalState:         getString(data["approval"]),
		FulfillmentGroup:      getString(data["assignment_group"]),
		AssignedTo:            getString(data["assigned_to"]),
		BusinessService:       getString(data["business_service"]),
		ConfigurationItem:     getString(data["cmdb_ci"]),
		DeliveryAddress:       getString(data["delivery_address"]),
		SpecialInstructions:   getString(data["special_instructions"]),
	}
}

func (rt *RequestTracker) parseCatalogTask(data map[string]interface{}) CatalogTask {
	return CatalogTask{
		SysID:            getString(data["sys_id"]),
		Number:           getString(data["number"]),
		State:            getString(data["state"]),
		RequestItemSysID: getString(data["request_item"]),
		ShortDescription: getString(data["short_description"]),
		Description:      getString(data["description"]),
		AssignedTo:       getString(data["assigned_to"]),
		AssignmentGroup:  getString(data["assignment_group"]),
		OpenedBy:         getString(data["opened_by"]),
		OpenedAt:         parseTime(getString(data["opened_at"])),
		DueDate:          parseTime(getString(data["due_date"])),
		ClosedAt:         parseTime(getString(data["closed_at"])),
		ClosedBy:         getString(data["closed_by"]),
		Priority:         getString(data["priority"]),
		WorkNotes:        getString(data["work_notes"]),
		CloseNotes:       getString(data["close_notes"]),
	}
}

// Helper functions

func parseTime(timeStr string) time.Time {
	if timeStr == "" {
		return time.Time{}
	}

	// Try different time formats that ServiceNow might use
	formats := []string{
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05.000Z",
		time.RFC3339,
	}

	for _, format := range formats {
		if t, err := time.Parse(format, timeStr); err == nil {
			return t
		}
	}

	return time.Time{}
}

func isHexString(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}