package catalog

import (
	"context"
	"fmt"
	"strconv"

	"github.com/Krive/ServiceNow-SDK/pkg/servicenow/core"
)

// CartItem represents an item in the shopping cart
type CartItem struct {
	SysID            string                 `json:"sys_id"`
	CatalogItemSysID string                 `json:"cat_item"`
	Quantity         int                    `json:"quantity"`
	Price            string                 `json:"price"`
	RecurringPrice   string                 `json:"recurring_price"`
	Variables        map[string]interface{} `json:"variables"`
	ItemDetails      *CatalogItem           `json:"item_details,omitempty"`
}

// Cart represents the shopping cart
type Cart struct {
	CartID     string     `json:"cart_id,omitempty"`
	Items      []CartItem `json:"items"`
	TotalPrice string     `json:"total_price"`
	Subtotal   string     `json:"subtotal"`
	Tax        string     `json:"tax"`
}

// AddToCartRequest represents a request to add an item to cart
type AddToCartRequest struct {
	CatalogItemSysID string                 `json:"sysparm_id"`
	Quantity         int                    `json:"sysparm_quantity"`
	Variables        map[string]interface{} `json:"variables"`
}

// AddToCartResponse represents the response from adding to cart
type AddToCartResponse struct {
	Success bool   `json:"success"`
	CartID  string `json:"cart_id"`
	ItemID  string `json:"item_id"`
	Message string `json:"message"`
	Error   string `json:"error,omitempty"`
}

// AddToCart adds a catalog item to the cart
func (cc *CatalogClient) AddToCart(itemSysID string, quantity int, variables map[string]interface{}) (*AddToCartResponse, error) {
	return cc.AddToCartWithContext(context.Background(), itemSysID, quantity, variables)
}

// AddToCartWithContext adds a catalog item to the cart with context support
func (cc *CatalogClient) AddToCartWithContext(ctx context.Context, itemSysID string, quantity int, variables map[string]interface{}) (*AddToCartResponse, error) {
	// Validate the item exists and variables are correct
	if err := cc.validateItemAndVariables(ctx, itemSysID, variables); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Prepare the request
	request := map[string]interface{}{
		"sysparm_quantity": quantity,
	}

	// Add variables if provided
	if len(variables) > 0 {
		request["variables"] = variables
	}

	// Use ServiceNow's Service Catalog API to add to cart
	var response map[string]interface{}
	err := cc.client.RawRootRequestWithContext(
		ctx,
		"POST",
		buildAddToCartPath(itemSysID),
		request,
		nil,
		&response,
		core.FormatJSON,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to add item to cart: %w", err)
	}

	// Parse the response
	cartResponse := &AddToCartResponse{
		Success: getBool(response["success"]),
		Message: getString(response["message"]),
		Error:   getString(response["error"]),
	}

	// Extract cart and item IDs if available
	if result, ok := response["result"].(map[string]interface{}); ok {
		cartResponse.CartID = getString(result["cart_id"])
		cartResponse.ItemID = getString(result["item_id"])
	}

	if !cartResponse.Success {
		return cartResponse, fmt.Errorf("failed to add to cart: %s", cartResponse.Error)
	}

	return cartResponse, nil
}

// GetCart returns the current cart contents
func (cc *CatalogClient) GetCart() (*Cart, error) {
	return cc.GetCartWithContext(context.Background())
}

// GetCartWithContext returns the current cart contents with context support
func (cc *CatalogClient) GetCartWithContext(ctx context.Context) (*Cart, error) {
	var response map[string]interface{}
	err := cc.client.RawRootRequestWithContext(
		ctx,
		"GET",
		buildCartPath(),
		nil,
		nil,
		&response,
		core.FormatJSON,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get cart: %w", err)
	}

	// Parse cart response
	cart := &Cart{
		Items: make([]CartItem, 0),
	}

	if result, ok := response["result"].(map[string]interface{}); ok {
		cart.CartID = extractCartID(result)
		cart.TotalPrice = getString(result["total_price"])
		cart.Subtotal = getString(result["subtotal"])
		cart.Tax = getString(result["tax"])

		// Parse cart items
		if items, ok := result["items"].([]interface{}); ok {
			for _, item := range items {
				if itemData, ok := item.(map[string]interface{}); ok {
					cartItem := CartItem{
						SysID:            getString(itemData["sys_id"]),
						CatalogItemSysID: getString(itemData["cat_item"]),
						Quantity:         getInt(itemData["quantity"]),
						Price:            getString(itemData["price"]),
						RecurringPrice:   getString(itemData["recurring_price"]),
					}

					// Parse variables if present
					if vars, ok := itemData["variables"].(map[string]interface{}); ok {
						cartItem.Variables = vars
					}

					cart.Items = append(cart.Items, cartItem)
				}
			}
		}
	}

	return cart, nil
}

// UpdateCartItem updates the quantity or variables of a cart item
func (cc *CatalogClient) UpdateCartItem(cartItemSysID string, quantity int, variables map[string]interface{}) error {
	return cc.UpdateCartItemWithContext(context.Background(), cartItemSysID, quantity, variables)
}

// UpdateCartItemWithContext updates cart item with context support
func (cc *CatalogClient) UpdateCartItemWithContext(ctx context.Context, cartItemSysID string, quantity int, variables map[string]interface{}) error {
	request := map[string]interface{}{
		"sysparm_quantity": quantity,
	}

	if len(variables) > 0 {
		request["variables"] = variables
	}

	var response map[string]interface{}
	err := cc.client.RawRootRequestWithContext(
		ctx,
		"PUT",
		buildCartItemPath(cartItemSysID),
		request,
		nil,
		&response,
		core.FormatJSON,
	)
	if err != nil {
		return fmt.Errorf("failed to update cart item: %w", err)
	}

	if !getBool(response["success"]) {
		return fmt.Errorf("failed to update cart item: %s", getString(response["error"]))
	}

	return nil
}

// RemoveFromCart removes an item from the cart
func (cc *CatalogClient) RemoveFromCart(cartItemSysID string) error {
	return cc.RemoveFromCartWithContext(context.Background(), cartItemSysID)
}

// RemoveFromCartWithContext removes an item from the cart with context support
func (cc *CatalogClient) RemoveFromCartWithContext(ctx context.Context, cartItemSysID string) error {
	var response map[string]interface{}
	err := cc.client.RawRootRequestWithContext(
		ctx,
		"DELETE",
		buildCartItemPath(cartItemSysID),
		nil,
		nil,
		&response,
		core.FormatJSON,
	)
	if err != nil {
		return fmt.Errorf("failed to remove item from cart: %w", err)
	}

	if !getBool(response["success"]) {
		return fmt.Errorf("failed to remove item from cart: %s", getString(response["error"]))
	}

	return nil
}

// ClearCart removes all items from the cart
func (cc *CatalogClient) ClearCart() error {
	return cc.ClearCartWithContext(context.Background())
}

// ClearCartWithContext clears the cart with context support
func (cc *CatalogClient) ClearCartWithContext(ctx context.Context) error {
	cart, err := cc.GetCartWithContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to resolve cart id before clear: %w", err)
	}
	if cart.CartID == "" {
		return fmt.Errorf("cart id not found in cart response")
	}

	var response map[string]interface{}
	err = cc.client.RawRootRequestWithContext(
		ctx,
		"DELETE",
		buildClearCartPath(cart.CartID),
		nil,
		nil,
		&response,
		core.FormatJSON,
	)
	if err != nil {
		return fmt.Errorf("failed to clear cart: %w", err)
	}

	if !getBool(response["success"]) {
		return fmt.Errorf("failed to clear cart: %s", getString(response["error"]))
	}

	return nil
}

// SubmitCart submits the current cart as an order
func (cc *CatalogClient) SubmitCart() (*OrderResult, error) {
	return cc.SubmitCartWithContext(context.Background())
}

// SubmitCartWithContext submits the cart with context support
func (cc *CatalogClient) SubmitCartWithContext(ctx context.Context) (*OrderResult, error) {
	var response map[string]interface{}
	err := cc.client.RawRootRequestWithContext(
		ctx,
		"POST",
		buildSubmitOrderPath(),
		nil,
		nil,
		&response,
		core.FormatJSON,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to submit cart: %w", err)
	}

	if !getBool(response["success"]) {
		return nil, fmt.Errorf("failed to submit cart: %s", getString(response["error"]))
	}

	// Parse the order result
	orderResult := &OrderResult{
		Success: true,
	}

	if result, ok := response["result"].(map[string]interface{}); ok {
		orderResult.RequestNumber = getString(result["request_number"])
		orderResult.RequestSysID = getString(result["request_id"])

		// Parse request items if present
		if items, ok := result["request_items"].([]interface{}); ok {
			for _, item := range items {
				if itemData, ok := item.(map[string]interface{}); ok {
					requestItem := RequestItem{
						SysID:  getString(itemData["sys_id"]),
						Number: getString(itemData["number"]),
						State:  getString(itemData["state"]),
						Stage:  getString(itemData["stage"]),
					}
					orderResult.RequestItems = append(orderResult.RequestItems, requestItem)
				}
			}
		}
	}

	return orderResult, nil
}

// OrderNow directly orders a catalog item without using the cart
func (cc *CatalogClient) OrderNow(itemSysID string, quantity int, variables map[string]interface{}) (*OrderResult, error) {
	return cc.OrderNowWithContext(context.Background(), itemSysID, quantity, variables)
}

// OrderNowWithContext directly orders an item with context support
func (cc *CatalogClient) OrderNowWithContext(ctx context.Context, itemSysID string, quantity int, variables map[string]interface{}) (*OrderResult, error) {
	// Validate the item exists and variables are correct
	if err := cc.validateItemAndVariables(ctx, itemSysID, variables); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Prepare the request
	request := map[string]interface{}{
		"sysparm_quantity": quantity,
	}

	// Add variables if provided
	if len(variables) > 0 {
		request["variables"] = variables
	}

	// Use ServiceNow's Service Catalog API to order directly
	var response map[string]interface{}
	err := cc.client.RawRootRequestWithContext(
		ctx,
		"POST",
		buildOrderNowPath(itemSysID),
		request,
		nil,
		&response,
		core.FormatJSON,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to order item: %w", err)
	}

	if !getBool(response["success"]) {
		return nil, fmt.Errorf("failed to order item: %s", getString(response["error"]))
	}

	// Parse the order result
	orderResult := &OrderResult{
		Success: true,
	}

	if result, ok := response["result"].(map[string]interface{}); ok {
		orderResult.RequestNumber = getString(result["request_number"])
		orderResult.RequestSysID = getString(result["request_id"])

		// Parse request items if present
		if items, ok := result["request_items"].([]interface{}); ok {
			for _, item := range items {
				if itemData, ok := item.(map[string]interface{}); ok {
					requestItem := RequestItem{
						SysID:  getString(itemData["sys_id"]),
						Number: getString(itemData["number"]),
						State:  getString(itemData["state"]),
						Stage:  getString(itemData["stage"]),
					}
					orderResult.RequestItems = append(orderResult.RequestItems, requestItem)
				}
			}
		}
	}

	return orderResult, nil
}

// EstimatePrice estimates the price for a catalog item with given variables
func (cc *CatalogClient) EstimatePrice(itemSysID string, quantity int, variables map[string]interface{}) (*PriceEstimate, error) {
	return cc.EstimatePriceWithContext(context.Background(), itemSysID, quantity, variables)
}

// EstimatePriceWithContext estimates price with context support
func (cc *CatalogClient) EstimatePriceWithContext(ctx context.Context, itemSysID string, quantity int, variables map[string]interface{}) (*PriceEstimate, error) {
	// Get the catalog item to get base price
	item, err := cc.GetItemWithContext(ctx, itemSysID)
	if err != nil {
		return nil, fmt.Errorf("failed to get item for price estimation: %w", err)
	}

	// Parse base price
	basePrice := parsePrice(item.Price)
	recurringPrice := parsePrice(item.RecurringPrice)

	estimate := &PriceEstimate{
		ItemSysID:      itemSysID,
		Quantity:       quantity,
		BasePrice:      basePrice,
		RecurringPrice: recurringPrice,
		TotalPrice:     basePrice * float64(quantity),
		TotalRecurring: recurringPrice * float64(quantity),
		Currency:       "USD", // Default, should be configurable
		Variables:      variables,
	}

	return estimate, nil
}

// PriceEstimate represents a price estimation for a catalog item
type PriceEstimate struct {
	ItemSysID      string                 `json:"item_sys_id"`
	Quantity       int                    `json:"quantity"`
	BasePrice      float64                `json:"base_price"`
	RecurringPrice float64                `json:"recurring_price"`
	TotalPrice     float64                `json:"total_price"`
	TotalRecurring float64                `json:"total_recurring"`
	Currency       string                 `json:"currency"`
	Variables      map[string]interface{} `json:"variables"`
	EstimatedDate  string                 `json:"estimated_date,omitempty"`
}

const serviceCatalogAPIBasePath = "/api/sn_sc/servicecatalog"

func buildAddToCartPath(itemSysID string) string {
	return fmt.Sprintf("%s/items/%s/add_to_cart", serviceCatalogAPIBasePath, itemSysID)
}

func buildCartPath() string {
	return fmt.Sprintf("%s/cart", serviceCatalogAPIBasePath)
}

func buildCartItemPath(cartItemSysID string) string {
	return fmt.Sprintf("%s/cart/%s", serviceCatalogAPIBasePath, cartItemSysID)
}

func buildClearCartPath(cartID string) string {
	return fmt.Sprintf("%s/cart/%s/empty", serviceCatalogAPIBasePath, cartID)
}

func buildSubmitOrderPath() string {
	return fmt.Sprintf("%s/cart/submit_order", serviceCatalogAPIBasePath)
}

func buildOrderNowPath(itemSysID string) string {
	return fmt.Sprintf("%s/items/%s/order_now", serviceCatalogAPIBasePath, itemSysID)
}

func extractCartID(result map[string]interface{}) string {
	cartID := getString(result["cart_id"])
	if cartID != "" {
		return cartID
	}
	return getString(result["sys_id"])
}

// validateItemAndVariables validates that an item exists and variables are valid
func (cc *CatalogClient) validateItemAndVariables(ctx context.Context, itemSysID string, variables map[string]interface{}) error {
	// Check if item exists
	_, err := cc.GetItemWithContext(ctx, itemSysID)
	if err != nil {
		return fmt.Errorf("catalog item not found: %w", err)
	}

	// Validate variables if provided
	if len(variables) > 0 {
		validationErrors, err := cc.ValidateItemVariablesWithContext(ctx, itemSysID, variables)
		if err != nil {
			return fmt.Errorf("variable validation failed: %w", err)
		}

		if len(validationErrors) > 0 {
			return fmt.Errorf("variable validation errors: %+v", validationErrors)
		}
	}

	return nil
}

// parsePrice converts a price string to float64
func parsePrice(priceStr string) float64 {
	if priceStr == "" {
		return 0.0
	}

	// Remove currency symbols and spaces
	cleanPrice := priceStr
	for _, symbol := range []string{"$", "€", "£", "¥", ",", " "} {
		cleanPrice = replaceAll(cleanPrice, symbol, "")
	}

	if price, err := strconv.ParseFloat(cleanPrice, 64); err == nil {
		return price
	}

	return 0.0
}

// replaceAll is a simple string replacement function
func replaceAll(s, old, new string) string {
	result := ""
	for i := 0; i < len(s); {
		if i <= len(s)-len(old) && s[i:i+len(old)] == old {
			result += new
			i += len(old)
		} else {
			result += string(s[i])
			i++
		}
	}
	return result
}
