package isql

import (
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"

	"github.com/apache/thrift/lib/go/thrift"
	"github.com/samber/lo"
	"github.com/sclgo/impala-go/internal/hive"
)

func mapErr(err error) error {
	if err == nil {
		return nil
	}
	var tErr thrift.TTransportException
	if errors.As(err, &tErr) {
		typeId := tErr.TypeId()
		if typeId == thrift.NOT_OPEN || typeId == thrift.END_OF_FILE {
			return wrapBadConn(err)
		}
	}

	var hiveStatusErr *hive.StatusError
	if errors.As(err, &hiveStatusErr) {
		// StatusCode, SqlState, and ErrorCode are not informative. SqlState = HY000 means "general error"
		if strings.Contains(lo.FromPtr(hiveStatusErr.Status().ErrorMessage), "Client session expired") {
			return wrapBadConn(err)
		}
	}

	if isOSBadConn(err) {
		return wrapBadConn(err)
	}

	return fmt.Errorf("impala: %w", err)
}

func wrapBadConn(err error) error {
	// the input error is intentionally not wrapped to avoid exposing internals
	// guideline: https://go.dev/blog/go1.13-errors
	return fmt.Errorf("%w inferred from error: %v", driver.ErrBadConn, err)
}
