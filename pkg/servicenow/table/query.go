package table

import (
	"fmt"
	"strings"
)

// Operator defines supported query operators
type Operator string

const (
	Eq         Operator = "="          // Equals
	NotEq      Operator = "!="         // Not equals
	Gt         Operator = ">"          // Greater than
	Lt         Operator = "<"          // Less than
	Gte        Operator = ">="         // Greater than or equals
	Lte        Operator = "<="         // Less than or equals
	Like       Operator = "LIKE"       // Contains substring
	NotLike    Operator = "NOTLIKE"    // Does not contain
	StartsWith Operator = "STARTSWITH" // Starts with
	EndsWith   Operator = "ENDSWITH"   // Ends with
	Contains   Operator = "CONTAINS"   // Contains (alias for LIKE with %)
	In         Operator = "IN"         // In list (comma-separated)
	NotIn      Operator = "NOTIN"      // Not in list
	IsEmpty    Operator = "ISEMPTY"    // Is empty
	IsNotEmpty Operator = "ISNOTEMPTY" // Is not empty
	Between    Operator = "BETWEEN"    // Between two values (e.g., "1@5")
	SameAs     Operator = "SAMEAS"     // Same as another field
	NotSameAs  Operator = "NSAMEAS"    // Not same as
)

// Logical defines logical connectors
type Logical string

const (
	And Logical = "^"   // AND
	Or  Logical = "^OR" // OR
	NQ  Logical = "^NQ" // NOT (negate query)
)

// QueryBuilder builds encoded sysparm_query strings
type QueryBuilder struct {
	clauses []string
	err     error
}

// NewQueryBuilder creates a new builder
func NewQueryBuilder() *QueryBuilder {
	return &QueryBuilder{}
}

// Add adds a field-operator-value clause with a logical connector
func (qb *QueryBuilder) Add(logical Logical, field string, op Operator, value interface{}) *QueryBuilder {
	if qb.err != nil {
		return qb
	}
	var clause string
	switch op {
	case Between:
		// Value must be string like "1@5"
		valStr, ok := value.(string)
		if !ok {
			qb.err = fmt.Errorf("BETWEEN requires string value like '1@5'")
			return qb
		}
		clause = fmt.Sprintf("%s%s%s", field, op, valStr)
	case In, NotIn:
		// Value can be slice or comma-separated string
		var vals string
		switch v := value.(type) {
		case string:
			vals = v
		case []string:
			vals = strings.Join(v, ",")
		default:
			qb.err = fmt.Errorf("%s requires string or []string value", op)
			return qb
		}
		clause = fmt.Sprintf("%s%s%s", field, op, vals)
	default:
		clause = fmt.Sprintf("%s%s%v", field, op, value)
	}
	qb.clauses = append(qb.clauses, string(logical)+clause)
	return qb
}

// And is a shortcut for Add with And logical
func (qb *QueryBuilder) And(field string, op Operator, value interface{}) *QueryBuilder {
	return qb.Add(And, field, op, value)
}

// Or is a shortcut for Add with Or logical
func (qb *QueryBuilder) Or(field string, op Operator, value interface{}) *QueryBuilder {
	return qb.Add(Or, field, op, value)
}

// Not is a shortcut for Add with NQ logical (negates the next clause)
func (qb *QueryBuilder) Not(field string, op Operator, value interface{}) *QueryBuilder {
	return qb.Add(NQ, field, op, value)
}

// OrderBy adds sorting (asc)
func (qb *QueryBuilder) OrderBy(field string) *QueryBuilder {
	if qb.err != nil {
		return qb
	}
	qb.clauses = append(qb.clauses, fmt.Sprintf("^ORDERBY%s", field))
	return qb
}

// OrderByDesc adds sorting (desc)
func (qb *QueryBuilder) OrderByDesc(field string) *QueryBuilder {
	if qb.err != nil {
		return qb
	}
	qb.clauses = append(qb.clauses, fmt.Sprintf("^ORDERBYDESC%s", field))
	return qb
}

// GroupBy adds grouping
func (qb *QueryBuilder) GroupBy(field string) *QueryBuilder {
	if qb.err != nil {
		return qb
	}
	qb.clauses = append(qb.clauses, fmt.Sprintf("^GROUPBY%s", field))
	return qb
}

// Build constructs the encoded query string
func (qb *QueryBuilder) Build() (string, error) {
	if qb.err != nil {
		return "", qb.err
	}
	if len(qb.clauses) == 0 {
		return "", nil // Empty query is valid (all records)
	}
	// First clause doesn't need leading ^
	query := qb.clauses[0]
	if strings.HasPrefix(query, "^") {
		query = query[1:] // Strip leading ^ if present
	}
	return strings.Join(append([]string{query}, qb.clauses[1:]...), ""), nil
}
