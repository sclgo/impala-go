package hive

import (
	"context"
	"log"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/sclgo/impala-go/services/cli_service"
	"github.com/stretchr/testify/require"
)

func TestDBMetadata_GetTablesSeq(t *testing.T) {
	t.Run("basic", func(t *testing.T) {
		mock := &thriftClient{}
		hive := &Client{
			client: mock,
			opts:   &Options{},
			log:    log.Default(),
		}
		dbMeta := DBMetadata{
			h:    &cli_service.TSessionHandle{},
			hive: hive,
		}

		opuuid := uuid.New()
		mock.getTablesStatus = cli_service.TStatusCode_SUCCESS_STATUS
		mock.getTablesResp = &cli_service.TGetTablesResp{
			OperationHandle: &cli_service.TOperationHandle{
				OperationId: &cli_service.THandleIdentifier{
					GUID: opuuid[:],
				},
			},
			Status: &cli_service.TStatus{
				StatusCode: mock.getTablesStatus,
			},
		}
		seq, errPtr := dbMeta.GetTablesSeq(context.Background(), "", "")
		require.NotNil(t, errPtr)
		require.NoError(t, *errPtr)
		slices.Collect(seq)
		require.NoError(t, *errPtr)
		require.NotZero(t, mock.closeCalls)
	})
}

type thriftClient struct {
	cli_service.TCLIService

	closeCalls      int
	getTablesResp   *cli_service.TGetTablesResp
	getTablesStatus cli_service.TStatusCode
}

func (m *thriftClient) GetTables(context.Context, *cli_service.TGetTablesReq) (*cli_service.TGetTablesResp, error) {
	return m.getTablesResp, nil
}

func (m *thriftClient) FetchResults(context.Context, *cli_service.TFetchResultsReq) (*cli_service.TFetchResultsResp, error) {
	return &cli_service.TFetchResultsResp{
		Status: &cli_service.TStatus{
			StatusCode: m.getTablesStatus,
		},
		HasMoreRows: nil,
		Results:     nil,
	}, nil
}

func (m *thriftClient) CloseOperation(context.Context, *cli_service.TCloseOperationReq) (*cli_service.TCloseOperationResp, error) {
	m.closeCalls++
	return &cli_service.TCloseOperationResp{
		Status: &cli_service.TStatus{
			StatusCode: cli_service.TStatusCode_SUCCESS_STATUS,
		},
	}, nil
}
