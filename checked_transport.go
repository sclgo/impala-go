package impala

import (
	"crypto/tls"

	"github.com/apache/thrift/lib/go/thrift"
	"github.com/murfffi/conncheck"
)

type checkedTransport struct {
	conn *tls.Conn
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
	// Due to THRIFT-5996, IsOpen on a TLS connection additionally needs murfffi/conncheck.
	return t.TTransport.IsOpen() && conncheck.Do(t.conn) != conncheck.StatusNotOpen
}
