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
// The zero value of Options is valid but not recommended.
type Options struct {
	Host     string
	Port     string
	Username string
	Password string

	UseLDAP    bool
	UseTLS     bool
	CACertPath string
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
