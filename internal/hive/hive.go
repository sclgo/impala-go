package hive

import (
	"errors"
	"fmt"

	"github.com/sclgo/impala-go/internal/services/cli_service"
)

const (
	// TimestampFormat is JDBC compliant timestamp format
	TimestampFormat = "2006-01-02 15:04:05.999999999"
)

// rpcResponse represents thrift rpc response
type rpcResponse interface {
	GetStatus() *cli_service.TStatus
}

func checkStatus(resp rpcResponse) error {
	status := resp.GetStatus()
	code := status.StatusCode

	switch code {
	case cli_service.TStatusCode_SUCCESS_STATUS,
		cli_service.TStatusCode_SUCCESS_WITH_INFO_STATUS,
		cli_service.TStatusCode_STILL_EXECUTING_STATUS:
		return nil
	case cli_service.TStatusCode_ERROR_STATUS:
		return errors.New(status.GetErrorMessage())
	case cli_service.TStatusCode_INVALID_HANDLE_STATUS:
		return errors.New("thrift: invalid handle")
	default:
		return fmt.Errorf("unexpected code: %d; message: %s", code, status.GetErrorMessage())
	}
}

func guid(b []byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
