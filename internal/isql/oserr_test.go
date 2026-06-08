package isql

import (
	"fmt"
	"net"
	"strconv"
	"testing"

	"github.com/murfffi/gorich/fi"
	"github.com/stretchr/testify/require"
)

func TestIsBadConn_Integration(t *testing.T) {
	port, connections := createSocket(t)
	clientConn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	require.NoError(t, err)
	serverConn := <-connections
	require.NoError(t, serverConn.(*net.TCPConn).SetLinger(0))
	require.NoError(t, serverConn.Close())
	_, err = clientConn.Read(make([]byte, 10))
	err = fmt.Errorf("foobar %w", err)
	require.True(t, isOSBadConn(err))
	require.NoError(t, clientConn.Close())
}

func createSocket(t *testing.T) (int, chan net.Conn) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	fi.CleanupF(t, listener.Close)
	connections := make(chan net.Conn, 1)
	go func() {
		var lerr error
		for lerr == nil {
			var conn net.Conn
			conn, lerr = listener.Accept()
			connections <- conn
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port, connections
}
