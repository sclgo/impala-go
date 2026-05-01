package isql

import (
	"database/sql/driver"
	"errors"
	"io"
	"testing"

	"github.com/apache/thrift/lib/go/thrift"
	"github.com/stretchr/testify/require"
)

func TestMapErr(t *testing.T) {
	t.Run("nil error", func(t *testing.T) {
		require.NoError(t, mapErr(nil))
	})

	t.Run("returns original non bad connection error", func(t *testing.T) {
		err := errors.New("some query error")

		mappedErr := mapErr(err)

		require.Same(t, err, mappedErr)
		require.NotErrorIs(t, mappedErr, driver.ErrBadConn)
	})

	t.Run("maps thrift not open transport error to bad connection", func(t *testing.T) {
		err := thrift.NewTTransportException(thrift.NOT_OPEN, "transport is not open")

		mappedErr := mapErr(err)

		require.ErrorIs(t, mappedErr, driver.ErrBadConn)
		require.ErrorContains(t, mappedErr, "inferred from error")
	})

	t.Run("maps thrift end of file transport error to bad connection", func(t *testing.T) {
		err := thrift.NewTTransportException(thrift.END_OF_FILE, io.EOF.Error())

		mappedErr := mapErr(err)

		require.ErrorIs(t, mappedErr, driver.ErrBadConn)
		require.ErrorContains(t, mappedErr, "inferred from error")
	})

	t.Run("does not map other thrift transport errors to bad connection", func(t *testing.T) {
		err := thrift.NewTTransportException(thrift.TIMED_OUT, "transport timed out")

		mappedErr := mapErr(err)

		require.Same(t, err, mappedErr)
		require.NotErrorIs(t, mappedErr, driver.ErrBadConn)
	})

	t.Run("maps broken pipe error message to bad connection", func(t *testing.T) {
		err := errors.New("write tcp: broken pipe")

		mappedErr := mapErr(err)

		require.ErrorIs(t, mappedErr, driver.ErrBadConn)
		require.ErrorContains(t, mappedErr, "inferred from error")
	})

	t.Run("maps connection reset error message to bad connection", func(t *testing.T) {
		err := errors.New("read tcp: connection reset by peer")

		mappedErr := mapErr(err)

		require.ErrorIs(t, mappedErr, driver.ErrBadConn)
		require.ErrorContains(t, mappedErr, "inferred from error")
	})
}
