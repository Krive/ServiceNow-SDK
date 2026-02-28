package catalog

import "strings"

// applyEncodedOrder appends ORDERBY clauses to sysparm_query, which is the
// documented sorting mechanism for encoded queries.
func applyEncodedOrder(params map[string]string, orderExpr string) {
	clauses := buildEncodedOrderClauses(orderExpr)
	if len(clauses) == 0 {
		return
	}

	encodedOrder := strings.Join(clauses, "^")
	if base := params["sysparm_query"]; base != "" {
		params["sysparm_query"] = base + "^" + encodedOrder
		return
	}
	params["sysparm_query"] = encodedOrder
}

func buildEncodedOrderClauses(orderExpr string) []string {
	var clauses []string

	for _, raw := range strings.Split(orderExpr, ",") {
		field, desc := parseOrderToken(raw)
		if field == "" {
			continue
		}

		if desc {
			clauses = append(clauses, "ORDERBYDESC"+field)
		} else {
			clauses = append(clauses, "ORDERBY"+field)
		}
	}

	return clauses
}

func parseOrderToken(token string) (string, bool) {
	raw := strings.TrimSpace(token)
	if raw == "" {
		return "", false
	}

	if strings.HasPrefix(raw, "-") {
		field := strings.TrimSpace(raw[1:])
		return sanitizeOrderField(field), true
	}

	parts := strings.Fields(raw)
	if len(parts) == 2 {
		switch {
		case strings.EqualFold(parts[0], "DESC"):
			return sanitizeOrderField(parts[1]), true
		case strings.EqualFold(parts[0], "ASC"):
			return sanitizeOrderField(parts[1]), false
		case strings.EqualFold(parts[1], "DESC"):
			return sanitizeOrderField(parts[0]), true
		case strings.EqualFold(parts[1], "ASC"):
			return sanitizeOrderField(parts[0]), false
		}
	}

	return sanitizeOrderField(raw), false
}

func sanitizeOrderField(field string) string {
	cleaned := sanitizeQueryTerm(field)
	return strings.ReplaceAll(cleaned, " ", "")
}
