//go:build !windows

package isql

func isOSBadConn(err error) bool {
	return false
}
