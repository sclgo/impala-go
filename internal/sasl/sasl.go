package sasl

import (
	"errors"
)

// Common SASL errors.
var (
	ErrUnexpectedClientResponse  = errors.New("sasl: unexpected client response")
	ErrUnexpectedServerChallenge = errors.New("sasl: unexpected server challenge")
)

// Mech is SASL mechanism token
type Mech string

// SASL mechanism tokens
const (
	MechPlain = "PLAIN"
)

// Options contains data related to SASL negotiation
type Options struct {
	Service  string
	Host     string
	Username string
	Password string

	// Mechanism, when set, is negotiated in place of PLAIN.
	Mechanism Mechanism
}

// Mechanism is a SASL mechanism the driver's caller implements, as GSSAPI's Kerberos exchange (RFC 4752),
// which the driver does not implement itself. It is one negotiation: the driver asks for a new one for each
// connection.
type Mechanism interface {
	// Name is the mechanism's name, as the server lists it: GSSAPI.
	Name() string
	// Start is the client's first message.
	Start() (initial []byte, err error)
	// Step answers the server's challenge. done reports the client's side finished: the server must not
	// complete the negotiation before it is.
	Step(challenge []byte) (response []byte, done bool, err error)
}

// Client is SASL client
type Client interface {
	Start(mechlist []string) (mech string, initial []byte, done bool, err error)
	Step(challenge []byte) (response []byte, done bool, err error)
	Free()
	InterpretReceiveEOF(transportError error) error
}
