package hive

import (
	"context"

	"github.com/sclgo/impala-go/internal/generated/cli_service"
)

// Session represents hive session
type Session struct {
	hive *Client
	h    *cli_service.TSessionHandle
}

// Ping checks the connection
func (s *Session) Ping(ctx context.Context) error {
	req := cli_service.TGetInfoReq{
		SessionHandle: s.h,
		InfoType:      cli_service.TGetInfoType_CLI_SERVER_NAME,
	}

	resp, err := s.hive.client.GetInfo(ctx, &req)
	if err != nil {
		return err
	}
	if err := s.checkStatus(resp); err != nil {
		return err
	}

	s.hive.log.Printf("ping. server name: %s", resp.InfoValue.GetStringValue())
	return nil
}

// ExecuteStatement returns hive operation
func (s *Session) ExecuteStatement(ctx context.Context, stmt string) (*Operation, error) {
	req := cli_service.TExecuteStatementReq{
		SessionHandle: s.h,
		Statement:     stmt,
	}
	resp, err := s.hive.client.ExecuteStatement(ctx, &req)

	if err != nil {
		return nil, err
	}
	if err := s.checkStatus(resp); err != nil {
		return nil, err
	}
	s.hive.log.Printf("execute operation: %s; stmt: %s; status code: %s", guid(resp.OperationHandle.OperationId.GUID), stmt, resp.GetStatus().GetStatusCode())
	s.hive.log.Printf("operation. has resultset: %v", resp.OperationHandle.GetHasResultSet())
	s.hive.log.Printf("operation. modified row count: %f", resp.OperationHandle.GetModifiedRowCount())
	return &Operation{h: resp.OperationHandle, hive: s.hive}, nil
}

func (s *Session) checkStatus(resp rpcResponse) error {
	err := checkStatus(resp)
	if err != nil {
		return err
	}
	if resp.GetStatus().IsSetInfoMessages() {
		for _, msg := range resp.GetStatus().GetInfoMessages() {
			s.hive.log.Printf("info message: %s", msg)
		}
	}
	return nil
}

func (s *Session) DBMetadata() DBMetadata {
	return DBMetadata{
		h:    s.h,
		hive: s.hive,
	}
}

// Close session
func (s *Session) Close(ctx context.Context) error {
	s.hive.log.Printf("close session: %v", guid(s.h.GetSessionId().GUID))
	req := cli_service.TCloseSessionReq{
		SessionHandle: s.h,
	}
	resp, err := s.hive.client.CloseSession(ctx, &req)
	if err != nil {
		return err
	}
	if err := s.checkStatus(resp); err != nil {
		return err
	}
	return nil
}
