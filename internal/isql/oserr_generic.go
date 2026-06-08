//go:build !windows && !unix

package isql

import "github.com/murfffi/gorich/helperr"

func isOSBadConn(err error) bool {
	// Looking at go stdlib code, it seems that both "broken pipe" and "reset" are not
	// specific error instances, so they can be checked only by message.
	// Possibly, the reason is that those messages come from the OS.
	return helperr.ContainsAny(err, "broken pipe", "connection reset by peer", "connection was aborted")
}
