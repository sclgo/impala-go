package sclerr

import (
	"io"
	"strings"
)

func CloseQuietly(v io.Closer) {
	_ = v.Close()
}

func ContainsAny(err error, subs ...string) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, substr := range subs {
		if strings.Contains(msg, substr) {
			return true
		}
	}
	return false
}
