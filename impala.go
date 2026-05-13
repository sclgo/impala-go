package impala

import (
	"database/sql"
	"io"
	"time"
)

func init() {
	sql.Register("impala", &Driver{})
}

// Options for impala driver connection
// It is recommended to copy DefaultOptions before customizing values.
// The zero value of Options is a valid, but not recommended, configuration.
// The default and recommended value of all fields is the zero value if not otherwise specified
// in DefaultOptions.
type Options struct {
	Host     string
	Port     string
	Username string
	Password string

	// ReuseSession disables resetting the session when database/sql SPI requests it.
	// The connection and session will still be validated. database/sql asks to reset the session
	// when it reuses a connection from its pool.
	//
	// All popular drivers don't reset the connection session even though it is required
	// by the database/sql/driver SPI. When this setting is enabled, this driver behaves consistently
	// with the other DB drivers in the ecosystem but diverges somewhat from documented database/sql behavior.
	//
	// This setting must be enabled when this driver is used in github.com/xo/usql.
	// `usql` returns the connection to the pool after each statement, relying on the typical driver behavior.
	ReuseSession bool

	UseLDAP bool

	UseTLS     bool
	CACertPath string

	// TlsInsecureSkipVerify configures the tls.Config InsecureSkipVerify flag for
	// a TLS connection to Impala. Behaves the same way as AllowSelfSignedCerts in the official JDBC driver.
	TLSInsecureSkipVerify bool

	BufferSize int
	BatchSize  int

	// MemoryLimit configures the MEM_LIMIT Impala property for the connection
	// https://impala.apache.org/docs/build/html/topics/impala_mem_limit.html
	MemoryLimit string
	// QueryTimeout in seconds - for QUERY_TIMEOUT_S session configuration value
	// https://impala.apache.org/docs/build/html/topics/impala_query_timeout_s.html
	QueryTimeout int

	LogOut io.Writer

	// TCP transport configuration

	// SocketTimeout configures the maximum socket idle time. 0 or negative value means no limit.
	// Configuring SocketTimeout together with setting a context deadline/timeout
	// also causes socket reads to be retried within the deadline (thrift behavior)
	SocketTimeout time.Duration

	// ConnectTimeout configures the max wait for initial connection to server. 0 or negative value means no limit.
	ConnectTimeout time.Duration
}

func (o *Options) systemCAStoreSelected() bool {
	return o.CACertPath == "" && !o.TLSInsecureSkipVerify
}

var (
	// DefaultOptions for impala driver
	DefaultOptions = Options{
		BatchSize:      1024,
		BufferSize:     4096,
		Port:           "21050",
		LogOut:         io.Discard,
		SocketTimeout:  5 * time.Second,
		ConnectTimeout: 10 * time.Second,
	}
)
