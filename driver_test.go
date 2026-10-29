package impala

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql/driver"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/jinzhu/copier"
	"github.com/murfffi/gorich/fi"
	"github.com/stretchr/testify/require"
)

func TestNewConnector(t *testing.T) {
	t.Run("driver", func(t *testing.T) {
		cnct := NewConnector(&Options{})
		require.IsType(t, &Driver{}, cnct.Driver())
		// check if returned driver.Driver instance is valid
		_, err := cnct.Driver().Open("foobar")
		require.ErrorIs(t, err, ErrBadDSN)
	})
}

func TestParseURI(t *testing.T) {
	tests := []struct {
		in  string
		out Options
	}{
		{
			"impala://localhost",
			Options{Host: "localhost"},
		},
		{
			"impala://localhost:21000",
			Options{Host: "localhost", Port: "21000"},
		},
		{
			"impala://admin@localhost",
			Options{Host: "localhost", Username: "admin"},
		},
		{
			"impala://admin:password@localhost",
			Options{Host: "localhost", Username: "admin", Password: "password"},
		},
		{
			"impala://admin:p%40ssw0rd@localhost",
			Options{Host: "localhost", Username: "admin", Password: "p@ssw0rd"},
		},
		{
			"impala://localhost?reuse-session=true",
			Options{Host: "localhost", ReuseSession: true},
		},
		{
			"impala://admin:p%40ssw0rd@localhost?auth=ldap",
			Options{Host: "localhost", Username: "admin", Password: "p@ssw0rd", UseLDAP: true},
		},
		{
			"impala://localhost?tls=true&ca-cert=/etc/ca.crt",
			Options{Host: "localhost", UseTLS: true, CACertPath: "/etc/ca.crt"},
		},
		{
			"impala://localhost?tls=true&tls-insecure-skip-verify=true",
			Options{Host: "localhost", UseTLS: true, TLSInsecureSkipVerify: true},
		},
		{
			"impala://localhost?batch-size=2048&buffer-size=2048",
			Options{Host: "localhost", BatchSize: 2048, BufferSize: 2048},
		},
		{
			"impala://localhost?mem-limit=1g",
			Options{Host: "localhost", MemoryLimit: "1g"},
		},
		{
			"impala://localhost?socket-timeout=1s",
			Options{Host: "localhost", SocketTimeout: 1 * time.Second},
		},
		{
			"impala://localhost?connect-timeout=1",
			Options{Host: "localhost", ConnectTimeout: 1 * time.Millisecond},
		},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			expected := DefaultOptions
			err := copier.CopyWithOption(&expected, tt.out, copier.Option{IgnoreEmpty: true})
			require.NoError(t, err)
			opts, err := parseURI(tt.in)
			require.NoError(t, err)
			require.Equal(t, expected, *opts)
		})
	}
}

func TestParseURI_Negative(t *testing.T) {
	drv := &Driver{}
	t.Run("scheme", func(t *testing.T) {
		_, err := drv.Open("notimpala://")
		require.ErrorIs(t, err, ErrBadDSN)
		require.ErrorContains(t, err, "notimpala")
	})
	t.Run("invalidurl", func(t *testing.T) {
		_, err := drv.Open("impala://user:pass???@localhost")
		require.ErrorIs(t, err, ErrBadDSN)
		require.ErrorContains(t, err, "parse")
	})
	for _, key := range []string{"batch-size", "buffer-size", "query-timeout", "tls", "socket-timeout", "connect-timeout"} {
		t.Run("invalid "+key, func(t *testing.T) {
			_, err := drv.Open(fmt.Sprintf("impala://localhost?%s=aa", key))
			require.ErrorIs(t, err, ErrBadDSN)
			require.ErrorContains(t, err, "invalid "+key)
		})
	}
	t.Run("invalid ca-cert", func(t *testing.T) {
		_, err := drv.Open("impala://localhost?tls=true&ca-cert=aa")
		require.ErrorIs(t, err, ErrBadDSN)
		require.ErrorContains(t, err, "certificate")
	})
}

func TestDriver_Integration(t *testing.T) {
	fi.SkipLongTest(t)

	port := createUnresponsiveSocket(t)
	t.Run("openUnresponsive", func(t *testing.T) {
		t.Run("plainSocketTimeout", func(t *testing.T) {
			opts := &Options{
				Host:          "localhost",
				Port:          strconv.Itoa(port),
				SocketTimeout: 100 * time.Millisecond,
			}
			conn, err := connect(context.Background(), opts)
			require.NoError(t, err)
			_, err = conn.OpenSession(context.Background()) // thrift ignores context in most cases
			require.ErrorIs(t, err, driver.ErrBadConn)
		})

		t.Run("tlsCtx", func(t *testing.T) {
			opts := &Options{
				Host:   "localhost",
				Port:   strconv.Itoa(port),
				UseTLS: true,
			}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			_, err := connect(ctx, opts)
			require.ErrorIs(t, err, ErrOpenFailed)
			require.ErrorIs(t, err, context.DeadlineExceeded)
		})

		// connect timeout is tested with TLS because, for plain sockets, that timeout
		// impacts only the initial TCP handshake. it is hard to create a test socket that
		// does that slowly enough.

		t.Run("tlsConnectTimeout", func(t *testing.T) {
			opts := &Options{
				Host:           "localhost",
				Port:           strconv.Itoa(port),
				UseTLS:         true,
				ConnectTimeout: 100 * time.Millisecond,
			}
			_, err := connect(context.Background(), opts)
			t.Log(err)
			require.ErrorIs(t, err, ErrOpenFailed)
			require.ErrorIs(t, err, context.DeadlineExceeded)
			// in this case, the context that exceeded its deadline was created in
			// one of the variants of net.Dial
			require.ErrorContains(t, err, "connect timeout")
		})
	})

}

func createUnresponsiveSocket(t *testing.T) int {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	fi.CleanupF(t, listener.Close)
	go func() {
		var lerr error
		for lerr == nil {
			_, lerr = listener.Accept()
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}

func TestGetTLSConfig(t *testing.T) {
	t.Run("zero options", func(t *testing.T) {
		conf, err := getTLSConfig(&Options{})
		require.NoError(t, err)
		require.False(t, conf.InsecureSkipVerify)
		require.Nil(t, conf.RootCAs)
	})
	t.Run("default", func(t *testing.T) {
		conf, err := getTLSConfig(&Options{TLSInsecureSkipVerify: true})
		require.NoError(t, err)
		require.True(t, conf.InsecureSkipVerify)
		require.Nil(t, conf.CipherSuites)
		require.Nil(t, conf.RootCAs)
	})
	t.Run("custom config is used as base and not modified", func(t *testing.T) {
		base := &tls.Config{
			MinVersion:   tls.VersionTLS12,
			ServerName:   "impala.example.com",
			CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
		}
		conf, err := getTLSConfig(&Options{TLSConfig: base, TLSInsecureSkipVerify: true})
		require.NoError(t, err)
		require.NotSame(t, base, conf)
		require.Equal(t, uint16(tls.VersionTLS12), conf.MinVersion)
		require.Equal(t, "impala.example.com", conf.ServerName)
		require.Equal(t, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384}, conf.CipherSuites)
		require.True(t, conf.InsecureSkipVerify)
		require.False(t, base.InsecureSkipVerify)
	})
	t.Run("CA certificate overrides custom root CAs", func(t *testing.T) {
		base := &tls.Config{RootCAs: x509.NewCertPool()}
		conf, err := getTLSConfig(&Options{TLSConfig: base, CACertPath: "functest/testssl/localhost.crt"})
		require.NoError(t, err)
		require.NotSame(t, base.RootCAs, conf.RootCAs)
		require.False(t, conf.RootCAs.Equal(base.RootCAs))
	})
}

func TestSystemCAStoreSelected(t *testing.T) {
	require.True(t, (&Options{}).systemCAStoreSelected())
	require.True(t, (&Options{TLSConfig: &tls.Config{}}).systemCAStoreSelected())
	require.False(t, (&Options{CACertPath: "ca.crt"}).systemCAStoreSelected())
	require.False(t, (&Options{TLSInsecureSkipVerify: true}).systemCAStoreSelected())
	require.False(t, (&Options{TLSConfig: &tls.Config{RootCAs: x509.NewCertPool()}}).systemCAStoreSelected())
}

func TestOpenTransport_TLSConfig(t *testing.T) {
	fi.SkipLongTest(t)

	const certPath = "functest/testssl/localhost.crt"
	// the test certificate is valid only for the DNS name "localhost"
	port, states := startTLSServer(t, certPath, "functest/testssl/localhost.key")
	tlsOpts := func(conf *tls.Config) *Options {
		return &Options{Host: "127.0.0.1", Port: port, UseTLS: true, CACertPath: certPath, TLSConfig: conf}
	}

	t.Run("custom settings reach the handshake", func(t *testing.T) {
		transport, _, err := openTransport(context.Background(), tlsOpts(&tls.Config{
			ServerName:   "localhost",
			MaxVersion:   tls.VersionTLS12,
			CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		}))
		require.NoError(t, err)
		fi.CleanupF(t, transport.Close)
		state := receiveState(t, states)
		require.Equal(t, "localhost", state.ServerName)
		require.Equal(t, uint16(tls.VersionTLS12), state.Version)
		require.Equal(t, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, state.CipherSuite)
	})

	t.Run("server name defaults to host", func(t *testing.T) {
		_, _, err := openTransport(context.Background(), tlsOpts(nil))
		var verifyErr *tls.CertificateVerificationError
		require.ErrorAs(t, err, &verifyErr)
	})

	t.Run("insecure skip verify in TLSConfig is overridden", func(t *testing.T) {
		opts := tlsOpts(&tls.Config{ServerName: "localhost", InsecureSkipVerify: true})
		opts.CACertPath = ""
		_, _, err := openTransport(context.Background(), opts)
		var verifyErr *tls.CertificateVerificationError
		require.ErrorAs(t, err, &verifyErr)
		require.ErrorContains(t, err, "using system root CAs")
	})

	t.Run("custom root CAs are not reported as system root CAs", func(t *testing.T) {
		opts := tlsOpts(&tls.Config{ServerName: "localhost", RootCAs: x509.NewCertPool()})
		opts.CACertPath = ""
		_, _, err := openTransport(context.Background(), opts)
		var verifyErr *tls.CertificateVerificationError
		require.ErrorAs(t, err, &verifyErr)
		require.NotContains(t, err.Error(), "using system root CAs")
	})
}

// startTLSServer starts a TLS server that completes handshakes and reports their connection state.
func startTLSServer(t *testing.T, certPath, keyPath string) (string, <-chan tls.ConnectionState) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	require.NoError(t, err)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	require.NoError(t, err)
	fi.CleanupF(t, listener.Close)
	states := make(chan tls.ConnectionState, 10)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			tlsConn := conn.(*tls.Conn)
			if tlsConn.Handshake() == nil {
				states <- tlsConn.ConnectionState()
			}
			_ = conn.Close()
		}
	}()
	return strconv.Itoa(listener.Addr().(*net.TCPAddr).Port), states
}

func receiveState(t *testing.T, states <-chan tls.ConnectionState) tls.ConnectionState {
	select {
	case state := <-states:
		return state
	case <-time.After(5 * time.Second):
		t.Fatal("server did not complete a TLS handshake")
		return tls.ConnectionState{}
	}
}
