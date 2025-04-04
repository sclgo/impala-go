package impala

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql/driver"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/apache/thrift/lib/go/thrift"
	"github.com/samber/lo"
	"github.com/sclgo/impala-go/internal/hive"
	"github.com/sclgo/impala-go/internal/isql"
	"github.com/sclgo/impala-go/internal/sasl"
)

// Sentinel errors that don't carry instance information

var (
	// ErrNotSupported means this operation is not supported by impala driver
	ErrNotSupported = isql.ErrNotSupported
)

// The following errors carry instance information so they are types, instead of sentinel values.

// AuthError indicates that there was an authentication or authorization failure.
// The error message documents the username that was used, if any.
// errors.Unwrap() returns the underlying error that was interpreted as auth. failure, if any.
// This error will not be top-level in the chain - earlier errors in the chain
// reflect the process during which the auth. error happened.
type AuthError = sasl.AuthError

const (
	badDSNErrorPrefix = "impala: bad DSN: "
)

// Driver to impala
type Driver struct{}

// Open creates new connection to impala using the given data source name. Implements driver.Driver.
// Returned error wraps any errors coming from thrift or stdlib - typically crypto or net packages.
// If TLS is requested, and server certificate fails validation, error chain includes *tls.CertificateVerificationError
// If there was an authentication error, error chain includes one of the exported auth. errors in this package.
func (d *Driver) Open(dsn string) (driver.Conn, error) {
	opts, err := parseURI(dsn)
	if err != nil {
		return nil, fmt.Errorf(badDSNErrorPrefix+"%w", err)
	}

	conn, err := connect(opts)
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
	auth := query.Get("auth")
	if auth == "ldap" {
		opts.UseLDAP = true
	}

	useTls, ok := query["tls"]
	if ok {
		v, err := strconv.ParseBool(useTls[0])
		if err != nil {
			return nil, fmt.Errorf("invalid tls value: %w", err)
		}
		opts.UseTLS = v
	}

	caCert, ok := query["ca-cert"]
	if ok {
		opts.CACertPath = caCert[0]
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

	logDest, ok := query["log"]
	if ok {
		if strings.ToLower(logDest[0]) == "stderr" {
			opts.LogOut = os.Stderr
		}
	}

	return &opts, nil
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
func (c *connector) Connect(context.Context) (driver.Conn, error) {
	// TTransport.Open doesn't support context. In general, Thrift almost always doesn't accept or ignores context.
	return connect(c.opts)
}

// Driver implements driver.Connector
func (c *connector) Driver() driver.Driver {
	return c.d
}

func connect(opts *Options) (*isql.Conn, error) {
	transport, tlsConf, err := configureTransport(opts)
	if err != nil {
		return nil, fmt.Errorf(badDSNErrorPrefix+"%w", err)
	}

	protocol := thrift.NewTBinaryProtocolConf(transport, &thrift.TConfiguration{
		// The following configuration is propagated to Transport / Socket
		TBinaryStrictRead:  lo.ToPtr(false),
		TBinaryStrictWrite: lo.ToPtr(true),
		TLSConfig:          tlsConf,
		// TODO SocketTimeout, ConnectTimeout Github #34
	})

	if err = transport.Open(); err != nil {
		addInfo := ""
		if tlsConf != nil && tlsConf.RootCAs == nil {
			addInfo = " using system root CAs"
		}
		return nil, fmt.Errorf("impala: failed to open connection%s: %w", addInfo, err)
	}

	logger := log.New(opts.LogOut, "impala: ", log.LstdFlags)

	tclient := thrift.NewTStandardClient(protocol, protocol)
	client := hive.NewClient(tclient, logger, &hive.Options{
		MaxRows:      int64(opts.BatchSize),
		MemLimit:     opts.MemoryLimit,
		QueryTimeout: opts.QueryTimeout,
	})

	return isql.NewConn(client, transport, logger), nil
}

func configureTransport(opts *Options) (thrift.TTransport, *tls.Config, error) {
	addr := net.JoinHostPort(opts.Host, opts.Port)

	var socket thrift.TTransport
	var tlsConf *tls.Config
	if opts.UseTLS {

		tlsConf = &tls.Config{}
		if certPath := opts.CACertPath; certPath != "" {
			caCertPool, err := readCert(certPath)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to read CA certificate: %w", err)
			}
			tlsConf.RootCAs = caCertPool
		}
		// otherwise "host's root CA set" is used

		// Configuration applied in protocol below
		socket = thrift.NewTSSLSocketConf(addr, &thrift.TConfiguration{
			// should generally be overwritten but setting just in case to avoid regressions like #50
			TLSConfig: tlsConf,
		})
	} else {
		socket = thrift.NewTSocketConf(addr, &thrift.TConfiguration{})
	}

	var transport thrift.TTransport
	var err error
	if opts.UseLDAP {

		if opts.Username == "" {
			return nil, nil, errors.New("provide username for LDAP auth")
		}

		// Empty password will be used if not provided.

		transport, err = sasl.NewTSaslTransport(socket, &sasl.Options{
			Host:     opts.Host,
			Username: opts.Username,
			Password: opts.Password,
		})

		if err != nil {
			// This never happens in the current version of thrift.
			// NewTSaslTransport always returns nil error
			return nil, nil, err
		}
	} else {
		transport = thrift.NewTBufferedTransport(socket, opts.BufferSize)
	}

	return transport, tlsConf, nil
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
