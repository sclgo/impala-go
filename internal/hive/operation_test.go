package hive

import (
	"context"
	"log"
	"testing"

	"github.com/sclgo/impala-go/internal/generated/cli_service"
	"github.com/sclgo/impala-go/internal/generated/impalaservice"
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

	t.Run("cancelled while running", func(t *testing.T) {
		mock := &opThriftClient{running: true}
		hive := &Client{client: mock, opts: &Options{}, log: log.Default()}
		op := &Operation{hive: hive, h: &cli_service.TOperationHandle{OperationId: &cli_service.THandleIdentifier{GUID: make([]byte, 16)}}}
		ctx, cancel := context.WithCancel(context.Background())
		mock.onStatus = cancel
		err := op.WaitToFinish(ctx)
		require.ErrorIs(t, err, context.Canceled)
		require.True(t, mock.cancelled)
	})

	t.Run("cancelled while fetching", func(t *testing.T) {
		mock := &opThriftClient{running: true}
		hive := &Client{client: mock, opts: &Options{}, log: log.Default()}
		op := &Operation{hive: hive, h: &cli_service.TOperationHandle{OperationId: &cli_service.THandleIdentifier{GUID: make([]byte, 16)}}}
		ctx, cancel := context.WithCancel(context.Background())
		mock.onFetch = cancel
		_, err := fetch(ctx, op)
		require.ErrorIs(t, err, context.Canceled)
		require.True(t, mock.cancelled)
	})
}

func TestCalcRowsAffected(t *testing.T) {
	tests := map[string]struct {
		modified, deleted int64
		want              int64
	}{
		"insert":         {modified: 3, want: 3},
		"kudu delete":    {modified: 2, want: 2},
		"iceberg delete": {deleted: 2, want: 2},
		"iceberg update": {modified: 2, deleted: 2, want: 2},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			resp := &impalaservice.TCloseImpalaOperationResp{DmlResult_: &impalaservice.TDmlResult_{
				RowsModified: map[string]int64{"": tt.modified},
				RowsDeleted:  map[string]int64{"": tt.deleted},
			}}
			require.Equal(t, tt.want, calcRowsAffected(resp))
		})
	}
}

type opThriftClient struct {
	called    bool
	running   bool
	cancelled bool
	onStatus  func()
	onFetch   func()
	impalaservice.ImpalaHiveServer2Service
}

func (c *opThriftClient) GetOperationStatus(ctx context.Context, _ *cli_service.TGetOperationStatusReq) (*cli_service.TGetOperationStatusResp, error) {
	c.called = true
	if !c.running {
		return &cli_service.TGetOperationStatusResp{}, ctx.Err()
	}
	if c.onStatus != nil {
		c.onStatus()
	}
	return &cli_service.TGetOperationStatusResp{
		Status:         &cli_service.TStatus{StatusCode: cli_service.TStatusCode_SUCCESS_STATUS},
		OperationState: cli_service.TOperationStatePtr(cli_service.TOperationState_RUNNING_STATE),
	}, nil
}

func (c *opThriftClient) FetchResults(_ context.Context, _ *cli_service.TFetchResultsReq) (*cli_service.TFetchResultsResp, error) {
	if c.onFetch != nil {
		c.onFetch()
	}
	return &cli_service.TFetchResultsResp{
		Status: &cli_service.TStatus{StatusCode: cli_service.TStatusCode_STILL_EXECUTING_STATUS},
	}, nil
}

func (c *opThriftClient) CancelOperation(_ context.Context, _ *cli_service.TCancelOperationReq) (*cli_service.TCancelOperationResp, error) {
	c.cancelled = true
	return &cli_service.TCancelOperationResp{Status: &cli_service.TStatus{StatusCode: cli_service.TStatusCode_SUCCESS_STATUS}}, nil
}
