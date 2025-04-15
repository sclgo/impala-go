package isql

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/apache/thrift/lib/go/thrift"
	"github.com/murfffi/gorich/helperr"
	"github.com/sclgo/impala-go/internal/hive"
)

var (
	// ErrNotSupported means this operation is not supported by impala driver
	ErrNotSupported = errors.New("impala: not supported")
)

// Conn to impala. It is not used concurrently by multiple goroutines.
type Conn struct {
	t       thrift.TTransport
	session *hive.Session
	client  *hive.Client
	log     *log.Logger
}

// Ping impala server
// Implements driver.Pinger
func (c *Conn) Ping(ctx context.Context) error {
	session, err := c.OpenSession(ctx)
	// returns err with ErrBadConn in chain if session is not already open and open fails
	if err != nil {
		return err
	}

	err = session.Ping(ctx)

	// Looking at go stdlib code, it seems that both "broken pipe" and "reset" are not
	// specific error instances, so they can be checked only by message.
	// Possibly, the reason is that those messages come from the OS.
	if helperr.ContainsAny(err, "broken pipe", "connection reset by peer") {
		err = fmt.Errorf("%w inferred from error: %v", driver.ErrBadConn, err)
	}
	// There can be other similar cases, but driver.ErrBadConn and Ping specs require us
	// to only return it in chain if we are certain.
	return err
}

// CheckNamedValue is called before passing arguments to the driver
// and is called in place of any ColumnConverter. CheckNamedValue must do type
// validation and conversion as appropriate for the driver.
func (c *Conn) CheckNamedValue(val *driver.NamedValue) error {
	t, ok := val.Value.(time.Time)
	if ok {
		val.Value = t.Format(hive.TimestampFormat)
		return nil
	}
	return driver.ErrSkip
}

// Prepare returns prepared statement
// Implements driver.Conn
func (c *Conn) Prepare(query string) (driver.Stmt, error) {
	return c.PrepareContext(context.Background(), query)
}

// PrepareContext returns prepared statement
// Implements driver.ConnPrepareContext
func (c *Conn) PrepareContext(_ context.Context, query string) (driver.Stmt, error) {
	return &Stmt{
		conn: c,
		stmt: template(query),
	}, nil
}

// QueryContext executes a query that may return rows
// Implements driver.QueryerContext
func (c *Conn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	session, err := c.OpenSession(ctx)
	if err != nil {
		return nil, err
	}

	tmpl := template(q)
	stmt := statement(tmpl, args)
	return query(ctx, session, stmt)
}

// ExecContext executes a query that doesn't return rows
// Implements driver.ExecerContext
func (c *Conn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	session, err := c.OpenSession(ctx)
	if err != nil {
		return nil, err
	}

	tmpl := template(q)
	stmt := statement(tmpl, args)
	return exec(ctx, session, stmt)
}

// Begin is not supported
// Implements driver.Conn
func (c *Conn) Begin() (driver.Tx, error) {
	return nil, ErrNotSupported
}

// OpenSession ensure opened session
func (c *Conn) OpenSession(ctx context.Context) (*hive.Session, error) {
	if c.session == nil {
		session, err := c.client.OpenSession(ctx)
		if err != nil {
			c.log.Printf("failed to open session: %v", err)
			return nil, fmt.Errorf("%w inferred from error: %v", driver.ErrBadConn, err)
		}
		c.session = session
	}
	return c.session, nil
}

// ResetSession closes hive session
// Implements driver.SessionResetter
func (c *Conn) ResetSession(ctx context.Context) error {
	if c.session != nil {
		if err := c.session.Close(ctx); err != nil {
			return err
		}
		c.session = nil
	}
	return nil
}

// Close connection
// Implements driver.Conn
func (c *Conn) Close() error {
	c.log.Printf("close connection")
	if c.session != nil {
		err := c.session.Close(context.Background())
		if err != nil {
			return fmt.Errorf("failed to close underlying session while closing connection: %w", err)
		}
	}

	if err := c.t.Close(); err != nil {
		return fmt.Errorf("failed to close underlying transport while closing connection: %w", err)
	}
	return nil
}

func NewConn(client *hive.Client, transport thrift.TTransport, logger *log.Logger) *Conn {
	return &Conn{
		t:      transport,
		client: client,
		log:    logger,
	}
}
