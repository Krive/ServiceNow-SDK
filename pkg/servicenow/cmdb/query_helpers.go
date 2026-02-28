package cmdb

import (
	"strings"
	"time"
)

func sanitizeEncodedQueryValue(value string) string {
	cleaned := strings.ReplaceAll(value, "^", " ")
	cleaned = strings.ReplaceAll(cleaned, "\n", " ")
	cleaned = strings.ReplaceAll(cleaned, "\r", " ")
	return cleaned
}

func formatEncodedQueryDateTime(value time.Time) string {
	return value.Format("2006-01-02 15:04:05")
}
