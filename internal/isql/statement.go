package isql

import (
	"context"
	"database/sql/driver"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/sclgo/impala-go/internal/hive"
)

// Stmt is statement
type Stmt struct {
	stmt string

	conn *Conn
}

// Close statement. No-op
func (s *Stmt) Close() error {
	return nil
}

// NumInput returns number of inputs
func (s *Stmt) NumInput() int {
	// -1 means the driver doesn't know how to count the number of
	// placeholders, so (database/sql) won't sanity check input
	// See https://cs.opensource.google/go/go/+/refs/tags/go1.23.4:src/database/sql/convert.go;l=109
	// We could implement counting placeholders in the future.
	return -1
}

// Stmt does not need to implement https://pkg.go.dev/database/sql/driver#NamedValueChecker
// if it wouldn't add anything to the Conn impl. of the same interface.

// Exec executes a query that doesn't return rows
func (s *Stmt) Exec([]driver.Value) (driver.Result, error) {
	// This implementation is never used in recent versions of Go - ExecContext is used instead
	// even when the user calls sql.Stmt.Exec(). Following the example in database/sql/fakedb_test.go
	// we can implement this as:
	panic("ExecContext was not called.")
}

// Query executes a query that may return rows
func (s *Stmt) Query([]driver.Value) (driver.Rows, error) {
	// Comment in Exec() above applies here as well.
	panic("QueryContext was not called.")
}

// QueryContext executes a query that may return rows
func (s *Stmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	return s.conn.QueryContext(ctx, s.stmt, args)
}

// ExecContext executes a query that doesn't return rows
func (s *Stmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	return s.conn.ExecContext(ctx, s.stmt, args)
}

// bind writes the arguments into the statement as literals, since Impala has no server-side parameters.
// Supports for ? placeholders mirrors the Hive and Impala JDBC drivers, providing compatibility with them;
// @pN and @name are the ordinal and named forms. Placeholders inside string literals, quoted identifiers,
// and comments are not placeholders. A statement without arguments is returned unchanged.
//
// Docs: https://impala.apache.org/docs/build/html/topics/impala_literals.html
// https://impala.apache.org/docs/build/html/topics/impala_identifiers.html
// JDBC impl: https://github.com/apache/hive/blob/83d98f42fc7/jdbc/src/java/org/apache/hive/jdbc/HivePreparedStatement.java#L141
func bind(query string, args []driver.NamedValue) (string, error) {
	if len(args) == 0 {
		return query, nil
	}

	var sb strings.Builder
	sb.Grow(len(query))
	positional := 0
	for i := 0; i < len(query); i++ {
		c := query[i]
		switch {
		case c == '\\':
			sb.WriteByte(c)
			if i+1 < len(query) {
				i++
				sb.WriteByte(query[i])
			}
		case c == '\'' || c == '"' || c == '`':
			end := quoteEnd(query, i)
			sb.WriteString(query[i:end])
			i = end - 1
		case c == '-' && strings.HasPrefix(query[i:], "--"):
			end := strings.IndexByte(query[i:], '\n')
			if end < 0 {
				end = len(query) - i
			}
			sb.WriteString(query[i : i+end])
			i += end - 1
		case c == '/' && strings.HasPrefix(query[i:], "/*"):
			end := strings.Index(query[i+2:], "*/")
			if end < 0 {
				end = len(query) - i
			} else {
				end += 4
			}
			sb.WriteString(query[i : i+end])
			i += end - 1
		case c == '?':
			positional++
			arg, ok := byOrdinal(args, positional)
			if !ok {
				return "", fmt.Errorf("%w: no argument for placeholder %d", ErrNotSupported, positional)
			}
			lit, err := literal(arg.Value)
			if err != nil {
				return "", err
			}
			sb.WriteString(lit)
		case c == '@':
			name := identifierAt(query, i+1)
			arg, ok := byPlaceholder(args, name)
			if !ok {
				sb.WriteByte(c)
				continue
			}
			lit, err := literal(arg.Value)
			if err != nil {
				return "", err
			}
			sb.WriteString(lit)
			i += len(name)
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String(), nil
}

// quoteEnd returns the index just past the quoted text that starts at i, or the statement's end.
func quoteEnd(query string, i int) int {
	quote := query[i]
	for j := i + 1; j < len(query); j++ {
		switch query[j] {
		case '\\':
			if quote != '`' {
				j++
			}
		case quote:
			return j + 1
		}
	}
	return len(query)
}

func identifierAt(query string, i int) string {
	j := i
	for j < len(query) && (query[j] == '_' || ('0' <= query[j] && query[j] <= '9') ||
		('a' <= query[j] && query[j] <= 'z') || ('A' <= query[j] && query[j] <= 'Z')) {
		j++
	}
	return query[i:j]
}

func byOrdinal(args []driver.NamedValue, ordinal int) (driver.NamedValue, bool) {
	for _, arg := range args {
		if arg.Name == "" && arg.Ordinal == ordinal {
			return arg, true
		}
	}
	return driver.NamedValue{}, false
}

func byPlaceholder(args []driver.NamedValue, name string) (driver.NamedValue, bool) {
	if name == "" {
		return driver.NamedValue{}, false
	}
	for _, arg := range args {
		if arg.Name == name {
			return arg, true
		}
	}
	if ordinal, err := strconv.Atoi(strings.TrimPrefix(name, "p")); err == nil && strings.HasPrefix(name, "p") {
		return byOrdinal(args, ordinal)
	}
	return driver.NamedValue{}, false
}

// literal renders a value as an Impala literal. A string's backslashes and single quotes are escaped with a
// backslash, which is how Impala reads them inside single quotes.
func literal(v any) (string, error) {
	switch v := v.(type) {
	case nil:
		return "NULL", nil
	case string:
		return quote(v), nil
	case []byte:
		return quote(string(v)), nil
	case bool:
		if v {
			return "TRUE", nil
		}
		return "FALSE", nil
	case int64:
		return strconv.FormatInt(v, 10), nil
	case float64:
		switch {
		case math.IsNaN(v):
			return "CAST('nan' AS DOUBLE)", nil
		case math.IsInf(v, 1):
			return "CAST('inf' AS DOUBLE)", nil
		case math.IsInf(v, -1):
			return "CAST('-inf' AS DOUBLE)", nil
		}
		return strconv.FormatFloat(v, 'g', -1, 64), nil
	default:
		return "", fmt.Errorf("%w: argument of type %T", ErrNotSupported, v)
	}
}

func quote(s string) string {
	var sb strings.Builder
	sb.Grow(len(s) + 2)
	sb.WriteByte('\'')
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' || s[i] == '\'' {
			sb.WriteByte('\\')
		}
		sb.WriteByte(s[i])
	}
	sb.WriteByte('\'')
	return sb.String()
}

func query(ctx context.Context, session *hive.Session, stmt string) (driver.Rows, error) {
	operation, err := session.ExecuteStatement(ctx, stmt)
	if err != nil {
		return nil, err
	}

	schema, err := operation.GetResultSetMetadata(ctx)
	if err != nil {
		_, _ = operation.Close(ctx)
		return nil, err
	}

	rs, err := operation.FetchResults(ctx, schema)
	if err != nil {
		return nil, err
	}

	return &Rows{
		rs:     rs,
		schema: schema,
		// TODO align context handling with database/sql practices (Github #14)
		closefn: func() error {
			_, err := operation.Close(ctx)
			return err
		},
	}, nil
}

func exec(ctx context.Context, session *hive.Session, stmt string) (driver.Result, error) {
	operation, err := session.ExecuteStatement(ctx, stmt)
	if err != nil {
		return nil, err
	}

	// wait for DDL/DML to finish like impala-shell :
	// https://github.com/apache/impala/blob/aac375e/shell/impala_shell.py#L1412
	err = operation.WaitToFinish(ctx)
	if err != nil {
		_, _ = operation.Close(ctx)
		return nil, err
	}

	rowsAffected, err := operation.Close(ctx)
	if err != nil {
		return nil, err
	}

	return driver.RowsAffected(rowsAffected), nil
}
