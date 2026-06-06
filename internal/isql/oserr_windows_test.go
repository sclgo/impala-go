//go:build windows

package isql

import (
	"fmt"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsOSBadConn(t *testing.T) {
	require.False(t, isOSBadConn(nil))
	require.True(t, isOSBadConn(fmt.Errorf("foobar %w", syscall.WSAECONNABORTED)))
}
