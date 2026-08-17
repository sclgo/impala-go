//go:build !windows && !unix

package isql

import "github.com/murfffi/gorich/helperr"

// isOSBadConn tells if the given OS error means that the driver must return driver.ErrBadConn
// This implementation is a fallback for rare platforms. Typically the code in oserr_unix and osserr_windows is used.
func isOSBadConn(err error) bool {
	return helperr.ContainsAny(err, "broken pipe", "connection reset by peer", "connection was aborted")
}
