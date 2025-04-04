package sasl

type plain struct {
	opts *Options
}

func newPlain(opts *Options) mech {
	return &plain{opts: opts}
}

func (m *plain) Start() (string, []byte, bool, error) {
	initial := []byte(m.opts.Username + "\x00" + m.opts.Username + "\x00" + m.opts.Password)
	return MechPlain, initial, true, nil
}

func (m *plain) Step(_ []byte) ([]byte, bool, error) {
	return nil, false, ErrUnexpectedServerChallenge
}

func (m *plain) InterpretReceiveEOF(transportError error) error {
	return &AuthError{
		username:       m.opts.Username,
		transportError: transportError,
	}
}
