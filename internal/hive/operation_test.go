package hive

import (
	"context"
	"log"
	"testing"

	"github.com/sclgo/impala-go/internal/generated/cli_service"
	"github.com/stretchr/testify/require"
)

func TestOperation(t *testing.T) {
	mock := &opThriftClient{}
	hive := &Client{
		client: mock,
		opts:   &Options{},
		log:    log.Default(),
	}

	t.Run("wait to finish", func(t *testing.T) {
		op := &Operation{
			hive: hive,
			h:    &cli_service.TOperationHandle{},
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := op.WaitToFinish(ctx)
		require.ErrorIs(t, err, context.Canceled)
		require.True(t, mock.called)
	})
}

type opThriftClient struct {
	called bool
	cli_service.TCLIService
}

func (c *opThriftClient) GetOperationStatus(ctx context.Context, _ *cli_service.TGetOperationStatusReq) (*cli_service.TGetOperationStatusResp, error) {
	c.called = true
	return &cli_service.TGetOperationStatusResp{}, ctx.Err()
}
