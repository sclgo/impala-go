package sasl

import (
	"fmt"
)

var supported = map[string]func(*Options) mech{
	MechPlain: newPlain,
}

// NewClient created new sasl client
func NewClient(opts *Options) Client {
	return &client{
		opts: opts,
	}
}

func (c *client) Start(mechlist []string) (string, []byte, bool, error) {
	if c.opts.Mechanism != nil {
		c.m = &external{opts: c.opts}
		return c.m.Start()
	}
	for _, mech := range mechlist {
		if newMech, ok := supported[mech]; ok {
			c.m = newMech(c.opts)
			return c.m.Start()
		}
	}
	return "", nil, false, fmt.Errorf("sasl: none of the provided mechs %v are supported", mechlist)
}

func (c *client) Step(challenge []byte) ([]byte, bool, error) {
	return c.m.Step(challenge)
}

func (c *client) InterpretReceiveEOF(transportError error) error {
	return c.m.InterpretReceiveEOF(transportError)
}

func (c *client) Free() {}

type mech interface {
	Start() (mech string, initial []byte, done bool, err error)
	Step(challenge []byte) (response []byte, done bool, err error)
	InterpretReceiveEOF(transportError error) error
}

type client struct {
	m    mech
	opts *Options
}

// external is the caller's Mechanism.
type external struct {
	opts *Options
}

func (m *external) Start() (string, []byte, bool, error) {
	initial, err := m.opts.Mechanism.Start()
	return m.opts.Mechanism.Name(), initial, false, err
}

func (m *external) Step(challenge []byte) ([]byte, bool, error) {
	return m.opts.Mechanism.Step(challenge)
}

func (m *external) InterpretReceiveEOF(transportError error) error {
	return &AuthError{
		username:       m.opts.Username,
		transportError: transportError,
	}
}
