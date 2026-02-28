package identity

import "strings"

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
	if desc {
		return "ORDERBYDESC" + order
	}
	return "ORDERBY" + order
}
