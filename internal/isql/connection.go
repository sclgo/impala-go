package isql

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/apache/thrift/lib/go/thrift"
	"github.com/sclgo/impala-go/internal/hive"
)

var (
	// ErrNotSupported means this operation is not supported by impala driver
	ErrNotSupported = errors.New("impala: not supported")
)

type Options struct {
	ReuseSession bool
}

// Conn to impala. It should not be used concurrently by multiple goroutines.
type Conn struct {
	transport thrift.TTransport // we use two methods: Close and IsOpen atm, make a dedicated iface if needed
	session   *hive.Session
	client    *hive.Client
	log       *log.Logger
	opts      Options
}

// This declaration lists and verifies driver interfaces implemented by *Conn
var _ interface {
	driver.Conn
	driver.Pinger
	driver.NamedValueChecker
	driver.ConnPrepareContext
	driver.QueryerContext
	driver.ExecerContext
	driver.SessionResetter
	driver.Validator
} = (*Conn)(nil)

// Ping impala server
// Implements driver.Pinger
func (c *Conn) Ping(ctx context.Context) error {
	session, err := c.OpenSession(ctx) // also validates transport; err has driver.ErrBadConn in chain
	if err != nil {
		return err
	}

	return mapErr(session.Ping(ctx))
}

// isTransportOpen checks if the underlying connection is open without doing a roundtrip
// and without blocking on IO. It can be used in cases where Ping will be too slow or unnecessary.
func (c *Conn) isTransportOpen() bool {
	// On TLS connections, the following call is eventually delegated to impala.checkedTransport.
	// On plain connections, we use the thrift implementation, which is Linux-only -
	// a non-blocking peek of a byte over the socket. Will be replaced with checkedTransport too soon.
	// See impala.openTransport in driver.go.
	return c.transport.IsOpen()
}

// CheckNamedValue is called before passing arguments to the driver
// and is called in place of any ColumnConverter. CheckNamedValue must do type
// validation and conversion as appropriate for the driver.
// Implements driver.NamedValueChecker
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
		stmt: query,
	}, nil
}

// QueryContext executes a query that may return rows
// Implements driver.QueryerContext
func (c *Conn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	session, err := c.OpenSession(ctx) // also validates transport; err has driver.ErrBadConn in chain
	if err != nil {
		return nil, err
	}

	tmpl := template(q)
	stmt := statement(tmpl, args)
	rows, err := query(ctx, session, stmt)
	return rows, mapErr(err)
}

// ExecContext executes a query that doesn't return rows
// Implements driver.ExecerContext
func (c *Conn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	session, err := c.OpenSession(ctx) // also validates transport; err has driver.ErrBadConn in chain
	if err != nil {
		return nil, err
	}

	tmpl := template(q)
	stmt := statement(tmpl, args)
	res, err := exec(ctx, session, stmt)
	return res, mapErr(err)
}

// Begin is not supported
// Implements driver.Conn
func (c *Conn) Begin() (driver.Tx, error) {
	return nil, ErrNotSupported
}

// OpenSession ensures opened session and live transport connection
// Any returned errors have driver.ErrBadConn in the chain
func (c *Conn) OpenSession(ctx context.Context) (*hive.Session, error) {
	if c.session == nil {
		session, err := c.client.OpenSession(ctx)
		if err != nil {
			err = fmt.Errorf("%w: failed to open session: %v", driver.ErrBadConn, err)
			c.log.Println(err)
			return nil, err
		}
		c.session = session
	} else {
		// since we are just about to reuse the existing session, quickly check if the transport is still open,
		// so we can return an error that database/sql/DB.retry can handle
		// This check is on the hot path before any query so if it turns out to be too expensive it should be disabled.
		if !c.isTransportOpen() {
			return nil, fmt.Errorf("%w: underlying connection is not open", driver.ErrBadConn)
		}
	}
	return c.session, nil
}

// ResetSession closes hive session
// Implements driver.SessionResetter
func (c *Conn) ResetSession(ctx context.Context) (err error) {
	if c.session != nil && !c.opts.ReuseSession {
		err = mapErr(c.session.Close(ctx))
		if err == nil {
			c.session = nil
			return nil // successfully closing the session means that connection is okay.
		}
	}

	if errors.Is(err, driver.ErrBadConn) {
		return err // getting ErrBadConn when resetting the session means that the connection is bad.
	}

	// database/sql uses ResetSession to both ask the driver to reset the session and to validate
	// a connection when taking it out of the pool. If we got here, we need to check.

	if !c.isTransportOpen() {
		return fmt.Errorf("%w: underlying connection was not open in ResetSession", driver.ErrBadConn)
	}

	return err
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

	if err := c.transport.Close(); err != nil {
		return fmt.Errorf("failed to close underlying transport while closing connection: %w", err)
	}
	return nil
}

// IsValid checks that the connection is valid for use in database/sql
// Implements driver.Validator
// database/sql calls this before the connection is returned to the pool, after it has just been used.
// In that case, running roundtrip validation like Ping is not worth the latency cost.
// This method is reserved for use by database/sql only. Internal code should call isTransportOpen instead.
// In the future, IsValid may do additional checks, not appropriate for other places isTransportOpen is called.
func (c *Conn) IsValid() bool {
	return c.isTransportOpen()
}

func NewConn(client *hive.Client, transport thrift.TTransport, logger *log.Logger, opts Options) *Conn {
	return &Conn{
		transport: transport,
		client:    client,
		log:       logger,
		opts:      opts,
	}
}
