package hive

import (
	"errors"
	"fmt"
	"testing"

	"github.com/samber/lo"
	"github.com/sclgo/impala-go/internal/generated/cli_service"
	"github.com/stretchr/testify/require"
)

func TestStatusError(t *testing.T) {
	t.Run("status", func(t *testing.T) {
		err := checkStatus(&cli_service.TGetInfoResp{Status: &cli_service.TStatus{
			StatusCode:   cli_service.TStatusCode_ERROR_STATUS,
			SqlState:     lo.ToPtr("HY000"),
			ErrorCode:    lo.ToPtr(int32(7)),
			ErrorMessage: lo.ToPtr("AnalysisException: no"),
		}})
		var se *StatusError
		require.True(t, errors.As(fmt.Errorf("impala: %w", err), &se))
		require.Equal(t, "AnalysisException: no", se.Message())
		require.Equal(t, "HY000", se.SQLState())
		require.EqualValues(t, 7, se.ErrorCode())
	})
	t.Run("state", func(t *testing.T) {
		err := checkState(&cli_service.TGetOperationStatusResp{
			OperationState: cli_service.TOperationStatePtr(cli_service.TOperationState_ERROR_STATE),
			ErrorMessage:   lo.ToPtr("Kudu error"),
		})
		var se *StatusError
		require.True(t, errors.As(err, &se))
		require.Equal(t, "Kudu error", se.Message())
	})
}
