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

var (
	// ErrNotSupported means this operation is not supported by impala driver
	ErrNotSupported = isql.ErrNotSupported
)

// Driver to impala
type Driver struct{}

// Open creates new connection to impala
func (d *Driver) Open(uri string) (driver.Conn, error) {
	opts, err := parseURI(uri)
	if err != nil {
		return nil, err
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

	if !strings.Contains(u.Host, ":") {
		u.Host = fmt.Sprintf("%s:%s", u.Host, DefaultOptions.Port)
	}

	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return nil, err
	}

	opts.Host = host
	opts.Port = port

	query := u.Query()
	auth := query.Get("auth")
	if auth == "ldap" {
		opts.UseLDAP = true
	}

	useTls, ok := query["tls"]
	if ok {
		v, err := strconv.ParseBool(useTls[0])
		if err != nil {
			return nil, err
		}
		opts.UseTLS = v
	}

	caCert, ok := query["ca-cert"]
	if ok {
		opts.CACertPath = caCert[0]
	}

	batchSize, ok := query["batch-size"]
	if ok {
		size, err := strconv.Atoi(batchSize[0])
		if err != nil {
			return nil, err
		}
		opts.BatchSize = size
	}

	bufferSize, ok := query["buffer-size"]
	if ok {
		size, err := strconv.Atoi(bufferSize[0])
		if err != nil {
			return nil, err
		}
		opts.BufferSize = size
	}

	memLimit, ok := query["mem-limit"]
	if ok {
		opts.MemoryLimit = memLimit[0]
	}

	queryTimeout, ok := query["query-timeout"]
	if ok {
		qTimeout, err := strconv.Atoi(queryTimeout[0])
		if err != nil {
			return nil, err
		}
		opts.QueryTimeout = qTimeout
	}

	logDest, ok := query["log"]
	if ok {
		if strings.ToLower(logDest[0]) == "stderr" {
			opts.LogOut = os.Stderr
		}
	}

	return &opts, nil
}

// OpenConnector parses name and return connector with fixed options
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
func (c *connector) Connect(context.Context) (driver.Conn, error) {
	// TTransport.Open doesn't support context. In general, Thrift almost always doesn't accept or ignores context.
	return connect(c.opts)
}

// Driver implements driver.Connector
func (c *connector) Driver() driver.Driver {
	return c.d
}

func connect(opts *Options) (*isql.Conn, error) {

	addr := net.JoinHostPort(opts.Host, opts.Port)

	var socket thrift.TTransport
	var tlsConf *tls.Config
	if opts.UseTLS {

		certPath := opts.CACertPath
		if certPath == "" {
			return nil, errors.New("impala: please provide CA certificate path")
		}

		caCertPool, err := readCert(certPath)
		if err != nil {
			return nil, fmt.Errorf("impala: failed to read CA certificate: %w", err)
		}

		tlsConf = &tls.Config{
			RootCAs: caCertPool,
		}
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
			return nil, errors.New("Please provide username for LDAP auth")
		}

		if opts.Password == "" {
			return nil, errors.New("Please provide password for LDAP auth")
		}

		transport, err = sasl.NewTSaslTransport(socket, &sasl.Options{
			Host:     opts.Host,
			Username: opts.Username,
			Password: opts.Password,
		})

		if err != nil {
			return nil, err
		}
	} else {
		transport = thrift.NewTBufferedTransport(socket, opts.BufferSize)
	}

	protocol := thrift.NewTBinaryProtocolConf(transport, &thrift.TConfiguration{
		// The following configuration is propagated to Transport / Socket
		TBinaryStrictRead:  lo.ToPtr(false),
		TBinaryStrictWrite: lo.ToPtr(true),
		TLSConfig:          tlsConf,
		// TODO SocketTimeout, ConnectTimeout Github #34
	})

	if err := transport.Open(); err != nil {
		return nil, fmt.Errorf("impala: failed to open connection: %w", err)
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
