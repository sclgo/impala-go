//go:build windows

package isql

import (
	"errors"
	"syscall"
)

// isOSBadConn: see oserr_generic.go
func isOSBadConn(err error) bool {
	var errNo syscall.Errno
	if !errors.As(err, &errNo) {
		return false
	}
	//goland:noinspection ALL
	res := errNo == syscall.WSAECONNRESET ||
		errNo == syscall.WSAECONNABORTED
	return res // for debug breakpoints
}
