package query

import (
	"fmt"
	"strconv"
	"strings"
)

// QueryBuilder provides a fluent interface for building ServiceNow encoded queries
type QueryBuilder struct {
	conditions []string
	orderBy    []string
	fields     []string
	limit      int
	offset     int
}

// Operator represents query operators
type Operator string

const (
	// Comparison operators
	OpEquals             Operator = "="
	OpNotEquals          Operator = "!="
	OpLessThan           Operator = "<"
	OpLessThanOrEqual    Operator = "<="
	OpGreaterThan        Operator = ">"
	OpGreaterThanOrEqual Operator = ">="
	OpStartsWith         Operator = "STARTSWITH"
	OpEndsWith           Operator = "ENDSWITH"
	OpContains           Operator = "CONTAINS"
	OpDoesNotContain     Operator = "DOESNOTCONTAIN"
	OpIn                 Operator = "IN"
	OpNotIn              Operator = "NOT IN"
	OpIsEmpty            Operator = "ISEMPTY"
	OpIsNotEmpty         Operator = "ISNOTEMPTY"
	OpBetween            Operator = "BETWEEN"
	OpSameAs             Operator = "SAMEAS"
	OpNotSameAs          Operator = "NSAMEAS"
	OpLike               Operator = "LIKE"
	OpNotLike            Operator = "NOTLIKE"

	// Date/time operators
	OpOn        Operator = "ON"
	OpNotOn     Operator = "NOTON"
	OpAfter     Operator = ">"
	OpBefore    Operator = "<"
	OpToday     Operator = "TODAY"
	OpYesterday Operator = "YESTERDAY"
	OpThisWeek  Operator = "THISWEEK"
	OpLastWeek  Operator = "LASTWEEK"
	OpThisMonth Operator = "THISMONTH"
	OpLastMonth Operator = "LASTMONTH"
	OpThisYear  Operator = "THISYEAR"
	OpLastYear  Operator = "LASTYEAR"

	// Logical operators
	OpAnd      Operator = "^"
	OpOr       Operator = "^OR"
	OpNot      Operator = "^NOT"
	OpNewQuery Operator = "^NQ"
)

// OrderDirection represents sort order
type OrderDirection string

const (
	OrderAsc  OrderDirection = "ASC"
	OrderDesc OrderDirection = "DESC"
)

// New creates a new QueryBuilder instance
func New() *QueryBuilder {
	return &QueryBuilder{
		conditions: make([]string, 0),
		orderBy:    make([]string, 0),
		fields:     make([]string, 0),
		limit:      0,
		offset:     0,
	}
}

// Where adds a basic condition to the query
func (q *QueryBuilder) Where(field string, operator Operator, value interface{}) *QueryBuilder {
	condition := fmt.Sprintf("%s%s%s", field, string(operator), formatValue(value))
	q.conditions = append(q.conditions, condition)
	return q
}

// Equals is a convenience method for equality comparison
func (q *QueryBuilder) Equals(field string, value interface{}) *QueryBuilder {
	return q.Where(field, OpEquals, value)
}

// NotEquals is a convenience method for inequality comparison
func (q *QueryBuilder) NotEquals(field string, value interface{}) *QueryBuilder {
	return q.Where(field, OpNotEquals, value)
}

// Contains is a convenience method for contains comparison
func (q *QueryBuilder) Contains(field string, value interface{}) *QueryBuilder {
	return q.Where(field, OpContains, value)
}

// StartsWith is a convenience method for starts with comparison
func (q *QueryBuilder) StartsWith(field string, value interface{}) *QueryBuilder {
	return q.Where(field, OpStartsWith, value)
}

// EndsWith is a convenience method for ends with comparison
func (q *QueryBuilder) EndsWith(field string, value interface{}) *QueryBuilder {
	return q.Where(field, OpEndsWith, value)
}

// GreaterThan is a convenience method for greater than comparison
func (q *QueryBuilder) GreaterThan(field string, value interface{}) *QueryBuilder {
	return q.Where(field, OpGreaterThan, value)
}

// LessThan is a convenience method for less than comparison
func (q *QueryBuilder) LessThan(field string, value interface{}) *QueryBuilder {
	return q.Where(field, OpLessThan, value)
}

// IsEmpty checks if field is empty
func (q *QueryBuilder) IsEmpty(field string) *QueryBuilder {
	return q.Where(field, OpIsEmpty, "")
}

// IsNotEmpty checks if field is not empty
func (q *QueryBuilder) IsNotEmpty(field string) *QueryBuilder {
	return q.Where(field, OpIsNotEmpty, "")
}

// In checks if field value is in the provided list
func (q *QueryBuilder) In(field string, values []interface{}) *QueryBuilder {
	valueStr := strings.Join(formatValues(values), ",")
	return q.Where(field, OpIn, valueStr)
}

// NotIn checks if field value is not in the provided list
func (q *QueryBuilder) NotIn(field string, values []interface{}) *QueryBuilder {
	valueStr := strings.Join(formatValues(values), ",")
	return q.Where(field, OpNotIn, valueStr)
}

// Between checks if field value is between two values
func (q *QueryBuilder) Between(field string, start, end interface{}) *QueryBuilder {
	value := fmt.Sprintf("javascript:gs.dateGenerate('%s','%s')", formatValue(start), formatValue(end))
	return q.Where(field, OpBetween, value)
}

// And adds an AND operator (this is the default behavior)
func (q *QueryBuilder) And() *QueryBuilder {
	if len(q.conditions) > 0 {
		q.conditions = append(q.conditions, string(OpAnd))
	}
	return q
}

// Or adds an OR operator
func (q *QueryBuilder) Or() *QueryBuilder {
	if len(q.conditions) > 0 {
		q.conditions = append(q.conditions, string(OpOr))
	}
	return q
}

// Not adds a NOT operator
func (q *QueryBuilder) Not() *QueryBuilder {
	q.conditions = append(q.conditions, string(OpNot))
	return q
}

// NewQuery starts a new query group
func (q *QueryBuilder) NewQuery() *QueryBuilder {
	if len(q.conditions) > 0 {
		q.conditions = append(q.conditions, string(OpNewQuery))
	}
	return q
}

// OrderBy adds ordering to the query
func (q *QueryBuilder) OrderBy(field string, direction OrderDirection) *QueryBuilder {
	orderStr := fmt.Sprintf("%s %s", field, string(direction))
	q.orderBy = append(q.orderBy, orderStr)
	return q
}

// OrderByAsc adds ascending order
func (q *QueryBuilder) OrderByAsc(field string) *QueryBuilder {
	return q.OrderBy(field, OrderAsc)
}

// OrderByDesc adds descending order
func (q *QueryBuilder) OrderByDesc(field string) *QueryBuilder {
	return q.OrderBy(field, OrderDesc)
}

// Fields specifies which fields to return
func (q *QueryBuilder) Fields(fields ...string) *QueryBuilder {
	q.fields = append(q.fields, fields...)
	return q
}

// Limit sets the maximum number of records to return
func (q *QueryBuilder) Limit(limit int) *QueryBuilder {
	q.limit = limit
	return q
}

// Offset sets the number of records to skip
func (q *QueryBuilder) Offset(offset int) *QueryBuilder {
	q.offset = offset
	return q
}

// Build constructs the final query parameters map
func (q *QueryBuilder) Build() map[string]string {
	params := make(map[string]string)

	// Build encoded query
	if queryStr := q.buildEncodedQuery(); queryStr != "" {
		params["sysparm_query"] = queryStr
	}

	// Add fields
	if len(q.fields) > 0 {
		params["sysparm_fields"] = strings.Join(q.fields, ",")
	}

	// Add limit
	if q.limit > 0 {
		params["sysparm_limit"] = strconv.Itoa(q.limit)
	}

	// Add offset
	if q.offset > 0 {
		params["sysparm_offset"] = strconv.Itoa(q.offset)
	}

	return params
}

// BuildQuery returns just the encoded query string
func (q *QueryBuilder) BuildQuery() string {
	return q.buildEncodedQuery()
}

func (q *QueryBuilder) buildEncodedQuery() string {
	base := strings.Join(q.conditions, "")
	if len(q.orderBy) == 0 {
		return base
	}

	var orderClauses []string
	for _, order := range q.orderBy {
		parts := strings.Fields(order)
		if len(parts) == 0 {
			continue
		}
		field := parts[0]
		if field == "" {
			continue
		}

		direction := ""
		if len(parts) > 1 {
			direction = strings.ToUpper(parts[len(parts)-1])
		}

		if direction == string(OrderDesc) {
			orderClauses = append(orderClauses, "ORDERBYDESC"+field)
		} else {
			orderClauses = append(orderClauses, "ORDERBY"+field)
		}
	}

	if len(orderClauses) == 0 {
		return base
	}
	if base == "" {
		return strings.Join(orderClauses, "^")
	}
	return base + "^" + strings.Join(orderClauses, "^")
}

// Clone creates a copy of the query builder
func (q *QueryBuilder) Clone() *QueryBuilder {
	clone := &QueryBuilder{
		conditions: make([]string, len(q.conditions)),
		orderBy:    make([]string, len(q.orderBy)),
		fields:     make([]string, len(q.fields)),
		limit:      q.limit,
		offset:     q.offset,
	}

	copy(clone.conditions, q.conditions)
	copy(clone.orderBy, q.orderBy)
	copy(clone.fields, q.fields)

	return clone
}

// Reset clears all conditions and settings
func (q *QueryBuilder) Reset() *QueryBuilder {
	q.conditions = q.conditions[:0]
	q.orderBy = q.orderBy[:0]
	q.fields = q.fields[:0]
	q.limit = 0
	q.offset = 0
	return q
}

// String returns a human-readable representation of the query
func (q *QueryBuilder) String() string {
	var parts []string

	if len(q.conditions) > 0 {
		parts = append(parts, fmt.Sprintf("WHERE: %s", strings.Join(q.conditions, "")))
	}

	if len(q.fields) > 0 {
		parts = append(parts, fmt.Sprintf("FIELDS: %s", strings.Join(q.fields, ", ")))
	}

	if len(q.orderBy) > 0 {
		parts = append(parts, fmt.Sprintf("ORDER BY: %s", strings.Join(q.orderBy, ", ")))
	}

	if q.limit > 0 {
		parts = append(parts, fmt.Sprintf("LIMIT: %d", q.limit))
	}

	if q.offset > 0 {
		parts = append(parts, fmt.Sprintf("OFFSET: %d", q.offset))
	}

	return strings.Join(parts, " | ")
}

// Helper functions

// formatValue converts a value to its string representation for queries
func formatValue(value interface{}) string {
	if value == nil {
		return ""
	}

	switch v := value.(type) {
	case string:
		return sanitizeEncodedQueryValue(v)
	case int, int8, int16, int32, int64:
		return fmt.Sprintf("%d", v)
	case uint, uint8, uint16, uint32, uint64:
		return fmt.Sprintf("%d", v)
	case float32, float64:
		return fmt.Sprintf("%g", v)
	case bool:
		if v {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", v)
	}
}

func sanitizeEncodedQueryValue(value string) string {
	cleaned := strings.ReplaceAll(value, "^", " ")
	cleaned = strings.ReplaceAll(cleaned, "\n", " ")
	cleaned = strings.ReplaceAll(cleaned, "\r", " ")
	return cleaned
}

// formatValues converts a slice of values to their string representations
func formatValues(values []interface{}) []string {
	result := make([]string, len(values))
	for i, value := range values {
		result[i] = formatValue(value)
	}
	return result
}

// Predefined query builders for common use cases

// ActiveRecords creates a query for active records
func ActiveRecords() *QueryBuilder {
	return New().Equals("active", true)
}

// InactiveRecords creates a query for inactive records
func InactiveRecords() *QueryBuilder {
	return New().Equals("active", false)
}

// RecentRecords creates a query for records created in the last N days
func RecentRecords(days int) *QueryBuilder {
	return New().Where("sys_created_on", OpGreaterThan, fmt.Sprintf("javascript:gs.daysAgoStart(%d)", days))
}

// UpdatedSince creates a query for records updated since a specific date
func UpdatedSince(date string) *QueryBuilder {
	return New().Where("sys_updated_on", OpGreaterThan, date)
}

// ByState creates a query for records with specific state
func ByState(state interface{}) *QueryBuilder {
	return New().Equals("state", state)
}

// ByPriority creates a query for records with specific priority
func ByPriority(priority interface{}) *QueryBuilder {
	return New().Equals("priority", priority)
}

// ByAssignedTo creates a query for records assigned to specific user
func ByAssignedTo(userID string) *QueryBuilder {
	return New().Equals("assigned_to", userID)
}

// SearchText creates a query that searches across multiple text fields
func SearchText(searchTerm string, fields ...string) *QueryBuilder {
	if len(fields) == 0 {
		// Default fields for text search
		fields = []string{"short_description", "description", "comments"}
	}

	q := New()
	for i, field := range fields {
		if i > 0 {
			q.Or()
		}
		q.Contains(field, searchTerm)
	}

	return q
}

// QuerySet provides a way to combine multiple queries
type QuerySet struct {
	queries []*QueryBuilder
}

// NewQuerySet creates a new query set
func NewQuerySet() *QuerySet {
	return &QuerySet{
		queries: make([]*QueryBuilder, 0),
	}
}

// Add adds a query to the set
func (qs *QuerySet) Add(query *QueryBuilder) *QuerySet {
	qs.queries = append(qs.queries, query)
	return qs
}

// Union combines all queries with OR
func (qs *QuerySet) Union() *QueryBuilder {
	if len(qs.queries) == 0 {
		return New()
	}

	if len(qs.queries) == 1 {
		return qs.queries[0].Clone()
	}

	result := New()
	for i, query := range qs.queries {
		if i > 0 {
			result.Or()
		}
		result.conditions = append(result.conditions, "("+query.BuildQuery()+")")
	}

	return result
}

// Intersection combines all queries with AND
func (qs *QuerySet) Intersection() *QueryBuilder {
	if len(qs.queries) == 0 {
		return New()
	}

	if len(qs.queries) == 1 {
		return qs.queries[0].Clone()
	}

	result := New()
	for i, query := range qs.queries {
		if i > 0 {
			result.And()
		}
		result.conditions = append(result.conditions, "("+query.BuildQuery()+")")
	}

	return result
}
