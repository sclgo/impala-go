package sasl

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/apache/thrift/lib/go/thrift"
)

type AuthError struct {
	username       string
	transportError error
}

// Error implements error
func (e *AuthError) Error() string {
	// message does not start with "impala: " because this error is expected to be wrapped
	// in a chain, reflecting the process during which the auth. error occurred.
	return fmt.Sprintf("authentication failed for user %s", e.username)
}

// Unwrap implements support for error.Is / As
func (e *AuthError) Unwrap() error {
	return e.transportError
}

var _ error = (*AuthError)(nil)

type TSaslTransport struct {
	rbuf *bytes.Buffer
	wbuf *bytes.Buffer

	trans thrift.TTransport
	sasl  Client
}

// Status is SASL negotiation status
type Status byte

// SASL negotiation statuses
const (
	StatusStart    Status = 1
	StatusOK       Status = 2
	StatusBad      Status = 3
	StatusError    Status = 4
	StatusComplete Status = 5
)

func NewTSaslTransport(t thrift.TTransport, opts *Options) (*TSaslTransport, error) {
	sasl := NewClient(opts)

	return &TSaslTransport{
		trans: t,
		sasl:  sasl,

		rbuf: bytes.NewBuffer(nil),
		wbuf: bytes.NewBuffer(nil),
	}, nil
}

func (t *TSaslTransport) IsOpen() bool {
	return t.trans.IsOpen()
}

func (t *TSaslTransport) Open() error {

	if !t.trans.IsOpen() {
		if err := t.trans.Open(); err != nil {
			return err
		}
	}

	mech, initial, _, err := t.sasl.Start([]string{MechPlain})
	if err != nil {
		return err
	}

	if err := t.negotiationSend(StatusStart, []byte(mech)); err != nil {
		return fmt.Errorf("sasl: negotiation failed. %w", err)
	}
	if err := t.negotiationSend(StatusOK, initial); err != nil {
		return fmt.Errorf("sasl: negotiation failed. %w", err)
	}

	for {
		status, challenge, err := t.receive()
		if err != nil {
			return fmt.Errorf("sasl: negotiation failed. %w", err)
		}

		if status != StatusOK && status != StatusComplete {
			return fmt.Errorf("sasl: negotiation failed. bad status: %d", status)
		}

		if status == StatusComplete {
			break
		}

		payload, _, err := t.sasl.Step(challenge)
		if err != nil {
			return fmt.Errorf("sasl: negotiation failed. %w", err)
		}
		if err := t.negotiationSend(StatusOK, payload); err != nil {
			return fmt.Errorf("sasl: negotiation failed. %w", err)
		}

	}
	return nil

}

func (t *TSaslTransport) Read(buf []byte) (int, error) {
	n, err := t.rbuf.Read(buf)
	if err != nil && err != io.EOF {
		return 0, err
	}
	if err == io.EOF {
		return t.readFrame(buf)
	}
	return n, nil
}

func (t *TSaslTransport) readFrame(buf []byte) (int, error) {
	header := make([]byte, 4)
	_, err := t.trans.Read(header)
	if err != nil {
		return 0, err
	}

	l := binary.BigEndian.Uint32(header)

	body := make([]byte, l)
	_, err = io.ReadFull(t.trans, body)
	if err != nil {
		return 0, err
	}
	t.rbuf = bytes.NewBuffer(body)
	return t.rbuf.Read(buf)
}

func (t *TSaslTransport) Write(buf []byte) (int, error) {
	return t.wbuf.Write(buf)
}

func (t *TSaslTransport) Flush(ctx context.Context) error {

	in, err := io.ReadAll(t.wbuf)
	if err != nil {
		return err
	}

	v := len(in)
	var payload []byte
	payload = append(payload, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	payload = append(payload, in...)

	wn, err := t.trans.Write(payload)
	if err != nil {
		return fmt.Errorf("sasl: write payload failed after %d bytes while flushing: %w", wn, err)
	}

	t.wbuf.Reset()
	return t.trans.Flush(ctx)
}

func (t *TSaslTransport) RemainingBytes() (num_bytes uint64) {
	return t.trans.RemainingBytes()
}

func (t *TSaslTransport) Close() error {
	t.sasl.Free()
	return t.trans.Close()
}

func (t *TSaslTransport) SetTConfiguration(conf *thrift.TConfiguration) {
	thrift.PropagateTConfiguration(t.trans, conf)
}

func (t *TSaslTransport) negotiationSend(status Status, body []byte) error {
	var payload []byte
	payload = append(payload, byte(status))
	v := len(body)
	payload = append(payload, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	payload = append(payload, body...)
	_, err := t.trans.Write(payload)
	if err != nil {
		return err
	}

	if err := t.trans.Flush(context.Background()); err != nil {
		return err
	}

	return nil
}

func (t *TSaslTransport) receive() (Status, []byte, error) {
	header := make([]byte, 5)
	_, err := t.trans.Read(header)
	if err != nil {
		var transportError thrift.TTransportException
		if errors.As(err, &transportError) {
			if transportError.TypeId() == thrift.END_OF_FILE {
				return 0, nil, t.sasl.InterpretReceiveEOF(err)
			}
		}
		return 0, nil, err
	}
	return Status(header[0]), header[1:], nil
}
