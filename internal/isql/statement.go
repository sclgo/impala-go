package isql

import (
	"context"
	"database/sql/driver"
	"fmt"
	"regexp"
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
func (s *Stmt) Exec(args []driver.Value) (driver.Result, error) {
	// This implementation is never used in recent versions of Go - ExecContext is used instead
	// even when the user calls sql.Stmt.Exec(). Following the example in database/sql/fakedb_test.go
	// we can implement this as:
	panic("ExecContext was not called.")
}

// Query executes a query that may return rows
func (s *Stmt) Query(args []driver.Value) (driver.Rows, error) {
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

// template replaces all ? placeholders with ordinal placeholders
// Supports for ? placeholders mirrors the Hive and Impala JDBC drivers,
// providing compatibility with them.
// '?' inside string literals or identifiers are allowed and are not placeholders.
func template(query string) string {
	if !strings.Contains(query, "?") {
		return query
	}

	// Docs:https://impala.apache.org/docs/build/html/topics/impala_literals.html
	// https://impala.apache.org/docs/build/html/topics/impala_identifiers.html
	// JDBC impl:https://github.com/apache/hive/blob/83d98f42fc7/jdbc/src/java/org/apache/hive/jdbc/HivePreparedStatement.java#L141

	var sb strings.Builder
	sb.Grow(len(query))
	ordinal := 1
	cntQuote := 0
	cntDQuote := 0
	cntBacktick := 0
	for i := 0; i < len(query); i++ {
		c := query[i]
		if c == '\\' {
			sb.WriteByte(c)
			if i+1 < len(query) {
				sb.WriteByte(query[i+1])
				i++
			}
			continue
		}

		var replaced bool
		switch c {
		case '"':
			if cntQuote%2 == 0 && cntBacktick%2 == 0 {
				cntDQuote++
			}
		case '\'':
			if cntDQuote%2 == 0 && cntBacktick%2 == 0 {
				cntQuote++
			}
		case '`':
			if cntQuote%2 == 0 && cntDQuote%2 == 0 {
				cntBacktick++
			}
		case '?':
			if cntQuote%2 == 0 && cntDQuote%2 == 0 && cntBacktick%2 == 0 {
				sb.WriteString(fmt.Sprintf("@p%d", ordinal))
				ordinal++
				replaced = true
			}
		}
		if !replaced {
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

func statement(tmpl string, args []driver.NamedValue) string {
	stmt := tmpl
	for _, arg := range args {
		var re *regexp.Regexp
		if arg.Name != "" {
			re = regexp.MustCompile(fmt.Sprintf("@%s%s", arg.Name, `\b`))
		} else {
			re = regexp.MustCompile(fmt.Sprintf("@p%d%s", arg.Ordinal, `\b`))
		}
		formatStr := "%v"
		if _, ok := arg.Value.(string); ok {
			formatStr = "'%v'"
		}
		val := fmt.Sprintf(formatStr, arg.Value)
		stmt = re.ReplaceAllString(stmt, val)
	}
	return stmt
}

func query(ctx context.Context, session *hive.Session, stmt string) (driver.Rows, error) {
	operation, err := session.ExecuteStatement(ctx, stmt)
	if err != nil {
		return nil, err
	}

	schema, err := operation.GetResultSetMetadata(ctx)
	if err != nil {
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
		return nil, err
	}

	rowsAffected, err := operation.Close(ctx)
	if err != nil {
		return nil, err
	}

	return driver.RowsAffected(rowsAffected), nil
}
