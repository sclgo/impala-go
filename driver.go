package impala

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/apache/thrift/lib/go/thrift"
	"github.com/samber/lo"
	"github.com/sclgo/impala-go/internal/hive"
	"github.com/sclgo/impala-go/internal/isql"
	"github.com/sclgo/impala-go/internal/sasl"
)

// Custom sentinel errors returned by the driver

var (
	// ErrNotSupported means the driver does not support this operation
	ErrNotSupported = isql.ErrNotSupported

	// ErrOpenFailed means the driver failed to open a connection.
	// Following database/sql docs, this is a separate error from driver.ErrBadConn.
	// If the root cause is context.DeadlineExceeded, AuthError, or *tls.CertificateVerificationError,
	// that cause will be in the same error tree as this sentinel, likely as a sibling.
	ErrOpenFailed = errors.New("impala: failed to open connection")

	// ErrBadDSN means the driver failed to parse the DSN or contained incorrect values.
	// Another error in the tree will describe the specific issue.
	ErrBadDSN = errors.New("impala: bad DSN")
)

// Custom error types returned by the driver

// AuthError indicates that there was an authentication or authorization failure.
// The error message documents the username used, if any.
// errors.Unwrap() returns the underlying error interpreted as auth. failure, if any.
// This error will not be top-level in the chain/tree - earlier errors
// reflect the process during which the error happened.
type AuthError = sasl.AuthError

// Driver to impala
type Driver struct{}

// Open creates a new connection to impala using the given data source name. Implements driver.Driver.
// The returned error contains ErrOpenFailed in the chain/tree, along with the specific cause.
// See ErrOpenFailed about which causes are guaranteed to be reported.
// The API does not guarantee the order of errors in the tree.
func (d *Driver) Open(dsn string) (driver.Conn, error) {
	opts, err := parseURI(dsn)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadDSN, err)
	}

	conn, err := connect(context.Background(), opts)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func parseURI(uri string) (*Options, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	// #21, https and http will be supported in the future for http transport
	// transport=http(s) will also be supported for usql/dburl compatibility

	if u.Scheme != "impala" {
		return nil, fmt.Errorf("scheme %s not recognized", u.Scheme)
	}

	opts := DefaultOptions

	if u.User != nil {
		opts.Username = u.User.Username()
		password, ok := u.User.Password()
		if ok {
			opts.Password = password
		}
	}

	opts.Host = u.Hostname()
	opts.Port = u.Port()

	if opts.Port == "" {
		opts.Port = DefaultOptions.Port
	}

	query := u.Query()

	err = parseBoolKey(query, "reuse-session", &opts.ReuseSession)
	if err != nil {
		return nil, err
	}

	auth := query.Get("auth")
	if auth == "ldap" {
		opts.UseLDAP = true
	}

	err = parseBoolKey(query, "tls", &opts.UseTLS)
	if err != nil {
		return nil, err
	}

	if opts.UseTLS {
		caCert, ok := query["ca-cert"]
		if ok {
			opts.CACertPath = caCert[0]
		}

		err = parseBoolKey(query, "tls-insecure-skip-verify", &opts.TLSInsecureSkipVerify)
		if err != nil {
			return nil, err
		}
	}

	err = parseIntKey(query, "batch-size", &opts.BatchSize)
	if err != nil {
		return nil, err
	}

	err = parseIntKey(query, "buffer-size", &opts.BufferSize)
	if err != nil {
		return nil, err
	}

	memLimit, ok := query["mem-limit"]
	if ok {
		opts.MemoryLimit = memLimit[0]
	}

	err = parseIntKey(query, "query-timeout", &opts.QueryTimeout)
	if err != nil {
		return nil, err
	}

	err = parseDurationKey(query, "socket-timeout", &opts.SocketTimeout)
	if err != nil {
		return nil, err
	}

	err = parseDurationKey(query, "connect-timeout", &opts.ConnectTimeout)
	if err != nil {
		return nil, err
	}

	logDest, ok := query["log"]
	if ok {
		if strings.ToLower(logDest[0]) == "stderr" {
			opts.LogOut = os.Stderr
		}
	}

	return &opts, nil
}

func parseBoolKey(query url.Values, key string, dest *bool) error {
	values, ok := query[key]
	if ok {
		val := values[0]
		v, err := strconv.ParseBool(val)
		if err != nil {
			return fmt.Errorf("invalid %s value: %s - %w", key, val, err)
		}
		*dest = v
	}
	return nil
}

func parseDurationKey(query url.Values, key string, target *time.Duration) (err error) {
	values, ok := query[key]
	if ok {
		*target, err = time.ParseDuration(values[0])
		if err != nil && strings.Contains(err.Error(), "missing unit in duration") {
			*target, err = time.ParseDuration(values[0] + "ms")
		}
		if err != nil {
			err = fmt.Errorf("invalid %s: %w", key, err)
		}
	}
	return
}

func parseIntKey(query url.Values, key string, target *int) (err error) {
	values, ok := query[key]
	if ok {
		*target, err = strconv.Atoi(values[0])
		if err != nil {
			err = fmt.Errorf("invalid %s: %w", key, err)
		}
	}
	return
}

// OpenConnector parses name as a DSN (data source name) and returns connector with fixed options
// Implements driver.DriverContext
func (d *Driver) OpenConnector(name string) (driver.Connector, error) {

	opts, err := parseURI(name)
	if err != nil {
		return nil, err
	}

	return &connector{opts: opts}, nil
}

type connector struct {
	d    *Driver
	opts *Options
}

// NewConnector creates connector with specified options
func NewConnector(opts *Options) driver.Connector {
	return &connector{opts: opts}
}

// Connect implements driver.Connector
// See Driver.Open for details about error results
func (c *connector) Connect(ctx context.Context) (driver.Conn, error) {
	// TTransport.Open doesn't support context. In general, Thrift almost always doesn't accept or ignores context.
	return connect(ctx, c.opts)
}

// Driver implements driver.Connector
func (c *connector) Driver() driver.Driver {
	return c.d
}

func connect(ctx context.Context, opts *Options) (*isql.Conn, error) {
	if opts.LogOut == nil {
		opts.LogOut = io.Discard
	}
	transport, tclient, err := connectThrift(ctx, opts)
	if err != nil {
		return nil, err
	}

	logger := log.New(opts.LogOut, "impala: ", log.LstdFlags)
	client := hive.NewClient(tclient, logger, &hive.Options{
		MaxRows:      int64(opts.BatchSize),
		MemLimit:     opts.MemoryLimit,
		QueryTimeout: opts.QueryTimeout,
	})

	return isql.NewConn(client, transport, logger, isql.Options{
		ReuseSession: opts.ReuseSession,
	}), nil
}

func openTransport(ctx context.Context, opts *Options) (thrift.TTransport, *thrift.TConfiguration, error) {
	var err error
	hostPort := net.JoinHostPort(opts.Host, opts.Port)

	conf := &thrift.TConfiguration{
		TBinaryStrictRead:  lo.ToPtr(false),
		TBinaryStrictWrite: lo.ToPtr(true),
		SocketTimeout:      opts.SocketTimeout,
		ConnectTimeout:     opts.ConnectTimeout,
	}

	var transport thrift.TTransport
	if opts.UseTLS {

		conf.TLSConfig, err = getTLSConfig(opts)
		if err != nil {
			return nil, nil, err
		}

		dialer := tls.Dialer{
			NetDialer: &net.Dialer{
				Timeout: conf.GetConnectTimeout(),
			},
			Config: conf.TLSConfig,
		}

		conn, err := dialer.DialContext(ctx, "tcp", hostPort)
		if err != nil {
			var addInfo string
			if opts.systemCAStoreSelected() {
				addInfo = " (using system root CAs)"
			}
			return nil, nil, wrapConnectErr(ctx, err, addInfo)
		}
		conn = augment(conn)
		transport = thrift.NewTSSLSocketFromConnConf(conn, conf)
		// this transport is open
	} else {
		transport = thrift.NewTSocketConf(hostPort, conf)
		if err := transport.Open(); err != nil {
			return nil, nil, wrapConnectErr(ctx, err, "")
		}
	}

	if opts.UseLDAP {

		if opts.Username == "" {
			return nil, nil, fmt.Errorf("%w: provide username for LDAP auth", ErrBadDSN)
		}

		// Empty password will be used if not provided.

		transport, err = sasl.NewTSaslTransport(transport, &sasl.Options{
			Host:     opts.Host,
			Username: opts.Username,
			Password: opts.Password,
		})

		if err != nil {
			// This never happens in the current version of thrift.
			// NewTSaslTransport always returns nil error
			return nil, nil, err
		}

		err = transport.Open()
		if err != nil {
			return nil, nil, fmt.Errorf("impala: authentication failed: %w", err)
		}
	} else {
		transport = thrift.NewTBufferedTransport(transport, opts.BufferSize)
	}

	return transport, conf, nil
}

func getTLSConfig(opts *Options) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: opts.TLSInsecureSkipVerify,
	}
	if certPath := opts.CACertPath; !opts.TLSInsecureSkipVerify && certPath != "" {
		caCertPool, err := readCert(certPath)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to read CA certificate: %w", ErrBadDSN, err)
		}
		tlsConfig.RootCAs = caCertPool
	}
	return tlsConfig, nil
}
func wrapConnectErr(ctx context.Context, err error, addInfo string) error {
	// Add information so the user can tell if "context deadline exceeded" means that
	// the ConnectTimeout was exceeded or the deadline was from the given context.
	// Internally, net.DialContext implements ConnectTimeout with a child context.
	if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
		// full message will be something like "connect timeout: context deadline exceeded"
		addInfo += " connect timeout context:"
	}
	return fmt.Errorf("%w:%s %w", ErrOpenFailed, addInfo, err)
}

func readCert(certPath string) (*x509.CertPool, error) {
	caCert, certErr := os.ReadFile(certPath)
	if certErr != nil {
		return nil, certErr
	}

	caCertPool := x509.NewCertPool()
	ok := caCertPool.AppendCertsFromPEM(caCert)
	if !ok {
		return nil, errors.New("failed to parse CA certificate")
	}
	return caCertPool, nil
}

func connectThrift(ctx context.Context, opts *Options) (thrift.TTransport, thrift.TClient, error) {
	transport, conf, err := openTransport(ctx, opts)

	if err != nil {
		return nil, nil, err
	}
	protocol := thrift.NewTBinaryProtocolConf(transport, conf)

	tclient := thrift.NewTStandardClient(protocol, protocol)
	return transport, tclient, nil
}
