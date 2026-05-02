package isql

import (
	"database/sql/driver"
	"errors"
	"fmt"

	"github.com/apache/thrift/lib/go/thrift"
	"github.com/murfffi/gorich/helperr"
)

func mapErr(err error) error {
	if err == nil {
		return nil
	}
	var tErr thrift.TTransportException
	if errors.As(err, &tErr) {
		typeId := tErr.TypeId()
		if typeId == thrift.NOT_OPEN || typeId == thrift.END_OF_FILE {
			return fmt.Errorf("%w inferred from error: %v", driver.ErrBadConn, err)
		}
	}

	// As a precaution, look for other indicators of ErrBadConn

	// Looking at go stdlib code, it seems that both "broken pipe" and "reset" are not
	// specific error instances, so they can be checked only by message.
	// Possibly, the reason is that those messages come from the OS.
	if helperr.ContainsAny(err, "broken pipe", "connection reset by peer") {
		return fmt.Errorf("%w inferred from error: %v", driver.ErrBadConn, err)
	}

	return err
}
