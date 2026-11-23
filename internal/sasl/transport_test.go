package sasl

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/apache/thrift/lib/go/thrift"
	"github.com/stretchr/testify/require"
)

type message struct {
	status Status
	body   string
}

type scriptedMechanism struct {
	challenges []string
	responses  []string
}

func (m *scriptedMechanism) Name() string { return "GSSAPI" }

func (m *scriptedMechanism) Start() ([]byte, error) { return []byte("initial"), nil }

func (m *scriptedMechanism) Step(challenge []byte) ([]byte, bool, error) {
	m.challenges = append(m.challenges, string(challenge))
	response := m.responses[0]
	m.responses = m.responses[1:]
	return []byte(response), len(m.responses) == 0, nil
}

func readMessage(r io.Reader) (message, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return message{}, err
	}
	body := make([]byte, binary.BigEndian.Uint32(header[1:]))
	if _, err := io.ReadFull(r, body); err != nil {
		return message{}, err
	}
	return message{status: Status(header[0]), body: string(body)}, nil
}

func writeMessage(w io.Writer, m message) error {
	b := []byte{byte(m.status), 0, 0, 0, 0}
	binary.BigEndian.PutUint32(b[1:], uint32(len(m.body)))
	_, err := w.Write(append(b, m.body...))
	return err
}

// serve answers each client message read with the reply at its index, past the two that open the negotiation,
// and returns what the client sent.
func serve(conn net.Conn, replies []message) <-chan []message {
	got := make(chan []message, 1)
	go func() {
		defer func() { _ = conn.Close() }()
		var sent []message
		defer func() { got <- sent }()
		for i := 0; ; i++ {
			m, err := readMessage(conn)
			if err != nil {
				return
			}
			sent = append(sent, m)
			if i == 0 {
				continue
			}
			if i-1 >= len(replies) {
				return
			}
			if err := writeMessage(conn, replies[i-1]); err != nil {
				return
			}
		}
	}()
	return got
}

func TestTSaslTransportOpen(t *testing.T) {
	tests := []struct {
		name       string
		mechanism  *scriptedMechanism
		replies    []message
		wantErr    string
		wantAuth   bool
		wantSent   []message
		challenges []string
	}{
		{
			name:      "a challenge reaches the mechanism as the message's body",
			mechanism: &scriptedMechanism{responses: []string{"", "layer"}},
			replies: []message{
				{StatusOK, "reply"},
				{StatusOK, "offer"},
				{StatusComplete, ""},
			},
			wantSent: []message{
				{StatusStart, "GSSAPI"},
				{StatusOK, "initial"},
				{StatusOK, ""},
				{StatusOK, "layer"},
			},
			challenges: []string{"reply", "offer"},
		},
		{
			name:       "the server completing before the mechanism is refused",
			mechanism:  &scriptedMechanism{responses: []string{"", "layer"}},
			replies:    []message{{StatusComplete, ""}},
			wantErr:    "the server completed it before the client",
			challenges: nil,
		},
		{
			name:       "a refusal carries the server's message",
			mechanism:  &scriptedMechanism{responses: []string{""}},
			replies:    []message{{StatusBad, "the ticket is for another service"}},
			wantErr:    "the ticket is for another service",
			wantAuth:   true,
			challenges: nil,
		},
		{
			name:     "PLAIN completes at once",
			replies:  []message{{StatusComplete, ""}},
			wantSent: []message{{StatusStart, "PLAIN"}, {StatusOK, "user\x00user\x00secret"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := net.Pipe()
			got := serve(server, tt.replies)
			opts := &Options{Username: "user", Password: "secret"}
			if tt.mechanism != nil {
				opts.Mechanism = tt.mechanism
			}
			transport, err := NewTSaslTransport(thrift.NewTSocketFromConnConf(client, nil), opts)
			require.NoError(t, err)
			err = transport.Open()
			_ = transport.Close()
			sent := <-got
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				var authErr *AuthError
				require.Equal(t, tt.wantAuth, errors.As(err, &authErr))
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantSent, sent)
			if tt.mechanism != nil {
				require.Equal(t, tt.challenges, tt.mechanism.challenges)
			}
		})
	}
}
