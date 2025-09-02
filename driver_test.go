package impala

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/jinzhu/copier"
	"github.com/murfffi/gorich/fi"
	"github.com/stretchr/testify/require"
)

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
			"impala://admin:p%40ssw0rd@localhost?auth=ldap",
			Options{Host: "localhost", Username: "admin", Password: "p@ssw0rd", UseLDAP: true},
		},
		{
			"impala://localhost?tls=true&ca-cert=/etc/ca.crt",
			Options{Host: "localhost", UseTLS: true, CACertPath: "/etc/ca.crt"},
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
		require.ErrorContains(t, err, badDSNErrorPrefix)
		require.ErrorContains(t, err, "notimpala")
	})
	t.Run("invalidurl", func(t *testing.T) {
		_, err := drv.Open("impala://user:pass???@localhost")
		require.ErrorContains(t, err, badDSNErrorPrefix)
		require.ErrorContains(t, err, "parse")
	})
	for _, key := range []string{"batch-size", "buffer-size", "query-timeout", "tls"} {
		t.Run("invalid "+key, func(t *testing.T) {
			_, err := drv.Open(fmt.Sprintf("impala://localhost?%s=aa", key))
			require.ErrorContains(t, err, badDSNErrorPrefix)
			require.ErrorContains(t, err, "invalid "+key)
		})
	}
	t.Run("invalid ca-cert", func(t *testing.T) {
		_, err := drv.Open("impala://localhost?tls=true&ca-cert=aa")
		require.ErrorContains(t, err, badDSNErrorPrefix)
		require.ErrorContains(t, err, "certificate")
	})
}

func TestDriver_Integration(t *testing.T) {
	fi.SkipLongTest(t)
	t.Run("openUnresponsive", func(t *testing.T) {
		port := createUnresponsiveSocket(t)

		opts := &Options{
			Host:          "localhost",
			Port:          strconv.Itoa(port),
			SocketTimeout: time.Second,
		}
		conn, err := connect(opts)
		require.NoError(t, err)
		_, err = conn.OpenSession(context.Background()) // thrift ignores context anyway in most cases
		require.ErrorContains(t, err, "bad connection")
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
