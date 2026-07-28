package impala

import (
	"net"
	"runtime"

	"github.com/apache/thrift/lib/go/thrift"
	"github.com/murfffi/conncheck"
)

type checkedTransport struct {
	conn net.Conn
	thrift.TTransport
}

func (t checkedTransport) SetTConfiguration(conf *thrift.TConfiguration) {
	thrift.PropagateTConfiguration(t.TTransport, conf)
}

var _ interface {
	thrift.TTransport
	thrift.TConfigurationSetter
} = checkedTransport{}

func (t checkedTransport) IsOpen() bool {
	// Due to THRIFT-6042, IsOpen on Windows additionally needs murfffi/conncheck.
	return t.TTransport.IsOpen() && (runtime.GOOS != "windows" || conncheck.Do(t.conn) != conncheck.StatusNotOpen)
}
