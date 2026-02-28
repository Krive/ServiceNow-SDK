package catalog

import "testing"

func TestServiceCatalogPathBuilders(t *testing.T) {
	if got := buildAddToCartPath("abc123"); got != "/api/sn_sc/servicecatalog/items/abc123/add_to_cart" {
		t.Fatalf("unexpected add_to_cart path: %s", got)
	}

	if got := buildCartPath(); got != "/api/sn_sc/servicecatalog/cart" {
		t.Fatalf("unexpected cart path: %s", got)
	}

	if got := buildCartItemPath("ci001"); got != "/api/sn_sc/servicecatalog/cart/ci001" {
		t.Fatalf("unexpected cart item path: %s", got)
	}

	if got := buildClearCartPath("cart001"); got != "/api/sn_sc/servicecatalog/cart/cart001/empty" {
		t.Fatalf("unexpected clear cart path: %s", got)
	}

	if got := buildSubmitOrderPath(); got != "/api/sn_sc/servicecatalog/cart/submit_order" {
		t.Fatalf("unexpected submit order path: %s", got)
	}

	if got := buildOrderNowPath("item001"); got != "/api/sn_sc/servicecatalog/items/item001/order_now" {
		t.Fatalf("unexpected order now path: %s", got)
	}
}

func TestExtractCartID(t *testing.T) {
	if got := extractCartID(map[string]interface{}{"cart_id": "cart123", "sys_id": "sys456"}); got != "cart123" {
		t.Fatalf("expected cart_id priority, got: %s", got)
	}

	if got := extractCartID(map[string]interface{}{"sys_id": "sys456"}); got != "sys456" {
		t.Fatalf("expected sys_id fallback, got: %s", got)
	}

	if got := extractCartID(map[string]interface{}{}); got != "" {
		t.Fatalf("expected empty cart id, got: %s", got)
	}
}
