package impala

import (
	"crypto/tls"
	"net"
	"syscall"
)

func augment(conn net.Conn) net.Conn {
	tlsConn, ok := conn.(*tls.Conn)
	if ok {
		if _, ok = tlsConn.NetConn().(syscall.Conn); ok {
			return augmentedTlsConn{tlsConn}
		}
	}
	return conn
}

// augmentedTlsConn implements interface syscall.Conn on *tls.Conn
// so the new conn can be used in Thrift socketConn.checkConn() on Unix
type augmentedTlsConn struct {
	*tls.Conn
}

func (a augmentedTlsConn) SyscallConn() (syscall.RawConn, error) {
	conn := a.NetConn()
	return conn.(syscall.Conn).SyscallConn()
}

var _ interface {
	syscall.Conn
	net.Conn
} = augmentedTlsConn{}
