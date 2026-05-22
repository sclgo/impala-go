package impala

import (
	"net"

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
	return conncheck.Do(t.conn) != conncheck.StatusNotOpen
}
