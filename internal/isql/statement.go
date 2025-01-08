package isql

import (
	"context"
	"database/sql/driver"
	"fmt"
	"regexp"
	"strings"
	"time"

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
	return -1
}

// CheckNamedValue is called before passing arguments to the driver
// and is called in place of any ColumnConverter. CheckNamedValue must do type
// validation and conversion as appropriate for the driver.
func (s *Stmt) CheckNamedValue(val *driver.NamedValue) error {
	t, ok := val.Value.(time.Time)
	if ok {
		val.Value = t.Format(hive.TimestampFormat)
		return nil
	}
	return driver.ErrSkip
}

// Exec executes a query that doesn't return rows
func (s *Stmt) Exec(args []driver.Value) (driver.Result, error) {
	// This implementation is never used in recent versions of Go - ExecContext is used instead
	// even when the user calls sql.Stmt.Exec(). We could implement this required interface method
	// with panic("not implemented") but we keep a full implementation just in case.
	nargs := toNamedValues(args)
	return s.ExecContext(context.Background(), nargs)
}

// Query executes a query that may return rows
func (s *Stmt) Query(args []driver.Value) (driver.Rows, error) {
	// Comment in Exec() above applies here as well.
	nargs := toNamedValues(args)
	return s.QueryContext(context.Background(), nargs)
}

// QueryContext executes a query that may return rows
func (s *Stmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	session, err := s.conn.OpenSession(ctx)
	if err != nil {
		return nil, err
	}
	stmt := statement(s.stmt, args)
	return query(ctx, session, stmt)
}

// ExecContext executes a query that doesn't return rows
func (s *Stmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	session, err := s.conn.OpenSession(ctx)
	if err != nil {
		return nil, err
	}
	stmt := statement(s.stmt, args)
	return exec(ctx, session, stmt)
}

func toNamedValues(args []driver.Value) []driver.NamedValue {
	// note that database/sql ensures Value never wraps a NamedValue so we don't need to check
	nargs := make([]driver.NamedValue, len(args))
	for i, arg := range args {
		nargs[i] = driver.NamedValue{Ordinal: i, Value: arg}
	}
	return nargs
}

func template(query string) string {
	ordinal := 1
	for {
		idx := strings.Index(query, "?")
		if idx == -1 {
			break
		}
		placeholder := fmt.Sprintf("@p%d", ordinal)
		query = strings.Replace(query, "?", placeholder, 1)
		ordinal++
	}
	return query
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
		closefn: func() error { return operation.Close(ctx) },
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

	// TODO (Github #3) Like impala-shell, use regex to check if statement is DML,
	// and use services.impalaservice.ImpalaServiceClient.CloseInsert to close operation
	// to be able to retrieve modified rows
	// DML_REGEX = re.compile("^(insert|upsert|update|delete)$", re.I)

	if err = operation.Close(ctx); err != nil {
		return nil, err
	}

	return driver.ResultNoRows, nil
}
