package impala

import (
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseURI(t *testing.T) {
	tests := []struct {
		in  string
		out Options
	}{
		{
			"impala://localhost",
			Options{Host: "localhost", Port: "21050", BatchSize: 1024, BufferSize: 4096, LogOut: io.Discard},
		},
		{
			"impala://localhost:21000",
			Options{Host: "localhost", Port: "21000", BatchSize: 1024, BufferSize: 4096, LogOut: io.Discard},
		},
		{
			"impala://admin@localhost",
			Options{Host: "localhost", Port: "21050", Username: "admin", BatchSize: 1024, BufferSize: 4096, LogOut: io.Discard},
		},
		{
			"impala://admin:password@localhost",
			Options{Host: "localhost", Port: "21050", Username: "admin", Password: "password", BatchSize: 1024, BufferSize: 4096, LogOut: io.Discard},
		},
		{
			"impala://admin:p%40ssw0rd@localhost",
			Options{Host: "localhost", Port: "21050", Username: "admin", Password: "p@ssw0rd", BatchSize: 1024, BufferSize: 4096, LogOut: io.Discard},
		},
		{
			"impala://admin:p%40ssw0rd@localhost?auth=ldap",
			Options{Host: "localhost", Port: "21050", Username: "admin", Password: "p@ssw0rd", UseLDAP: true, BatchSize: 1024, BufferSize: 4096, LogOut: io.Discard},
		},
		{
			"impala://localhost?tls=true&ca-cert=/etc/ca.crt",
			Options{Host: "localhost", Port: "21050", UseTLS: true, CACertPath: "/etc/ca.crt", BatchSize: 1024, BufferSize: 4096, LogOut: io.Discard},
		},
		{
			"impala://localhost?tls=true",
			Options{Host: "localhost", Port: "21050", UseTLS: true, BatchSize: 1024, BufferSize: 4096, LogOut: io.Discard},
		},
		{
			"impala://localhost?batch-size=2048&buffer-size=2048",
			Options{Host: "localhost", Port: "21050", BatchSize: 2048, BufferSize: 2048, LogOut: io.Discard},
		},
		{
			"impala://localhost?mem-limit=1g",
			Options{Host: "localhost", Port: "21050", BatchSize: 1024, BufferSize: 4096, LogOut: io.Discard, MemoryLimit: "1g"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			opts, err := parseURI(tt.in)
			require.NoError(t, err)
			require.Equal(t, tt.out, *opts)
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
