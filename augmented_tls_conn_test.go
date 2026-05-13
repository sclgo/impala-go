package impala

import (
	"crypto/tls"
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAugment(t *testing.T) {
	tlsConn := tls.Client(&net.TCPConn{}, nil)
	require.NotImplements(t, (*syscall.Conn)(nil), tlsConn)
	conn := augment(tlsConn)
	require.Implements(t, (*syscall.Conn)(nil), conn)
}
