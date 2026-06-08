//go:build unix

package isql

import (
	"errors"
	"syscall"
)

func isOSBadConn(err error) bool {
	var errNo syscall.Errno
	if !errors.As(err, &errNo) {
		return false
	}
	//goland:noinspection ALL
	res := errNo == syscall.ECONNRESET ||
		errNo == syscall.ECONNABORTED ||
		errNo == syscall.EPIPE
	return res // for debug breakpoints
}
