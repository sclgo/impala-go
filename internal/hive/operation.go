package hive

import (
	"context"
	"strings"
	"time"

	"github.com/sclgo/impala-go/internal/generated/cli_service"
	"github.com/sclgo/impala-go/internal/generated/impalaservice"
)

const (
	initialBackoff = 100 * time.Millisecond
	maxBackoff     = time.Second
)

// Operation represents hive operation
type Operation struct {
	hive *Client
	h    *cli_service.TOperationHandle
}

// HasResultSet return if operation has result set
func (op *Operation) HasResultSet() bool {
	return op.h.GetHasResultSet()
}

// RowsAffected return number of rows affected by operation
func (op *Operation) RowsAffected() float64 {
	return op.h.GetModifiedRowCount()
}

// GetResultSetMetadata return schema
func (op *Operation) GetResultSetMetadata(ctx context.Context) (*TableSchema, error) {
	op.hive.log.Printf("fetch metadata for operation: %v", guid(op.h.OperationId.GUID))
	req := cli_service.TGetResultSetMetadataReq{
		OperationHandle: op.h,
	}

	resp, err := op.hive.client.GetResultSetMetadata(ctx, &req)
	if err != nil {
		return nil, err
	}
	if err := checkStatus(resp); err != nil {
		return nil, err
	}

	schema := new(TableSchema)

	if resp.IsSetSchema() {
		for _, desc := range resp.Schema.Columns {
			entry := desc.TypeDesc.Types[0].PrimitiveEntry
			typeQualifiers := map[string]*cli_service.TTypeQualifierValue{}
			if entry.TypeQualifiers != nil {
				typeQualifiers = (*entry.TypeQualifiers).Qualifiers
			}
			dbtype := strings.TrimSuffix(entry.Type.String(), "_TYPE")
			maxLength, hasLength := getMaxLength(typeQualifiers)
			precision, scale, hasPrecisionScale := getPrecisionScale(typeQualifiers)
			schema.Columns = append(schema.Columns, &ColDesc{
				Name:              desc.ColumnName,
				DatabaseTypeName:  dbtype,
				ScanType:          typeOf(entry),
				HasLength:         hasLength,
				Length:            maxLength,
				Precision:         precision,
				Scale:             scale,
				HasPrecisionScale: hasPrecisionScale,
			})
		}

		for _, col := range schema.Columns {
			op.hive.log.Printf("fetch schema: %v", col)
		}
	}

	return schema, nil
}

// FetchResults lazily prepares query result from server
func (op *Operation) FetchResults(ctx context.Context, schema *TableSchema) (*ResultSet, error) {
	// Impala server prepares and buffers the query results before they are fetched.
	rs := ResultSet{
		idx:    0,
		length: 0,
		result: nil,
		more:   true,
		schema: schema,
		// TODO align query context handling with database/sql practices (Github #14)
		fetchfn: func() (*cli_service.TFetchResultsResp, error) { return fetch(ctx, op) },
	}
	return &rs, nil
}

// CheckStateAndStatus returns the operation state if both the state and status are ok
func (op *Operation) CheckStateAndStatus(ctx context.Context) (cli_service.TOperationState, error) {
	req := cli_service.TGetOperationStatusReq{
		OperationHandle: op.h,
	}
	resp, err := op.hive.client.GetOperationStatus(ctx, &req)
	if err != nil {
		return 0, err
	}
	if err = checkStatus(resp); err != nil {
		return 0, err
	}
	if err = checkState(resp); err != nil {
		return 0, err
	}
	state := resp.GetOperationState()
	op.hive.log.Println("op", guid(op.h.GetOperationId().GetGUID()), "reached success or non-terminal state", state)
	return state, nil
}

// WaitToFinish waits for the operation to reach a FINISHED state
// Returns error if the operation fails or the context is cancelled.
func (op *Operation) WaitToFinish(ctx context.Context) error {
	duration := initialBackoff
	opState, err := op.CheckStateAndStatus(ctx)
	for err == nil && opState != cli_service.TOperationState_FINISHED_STATE {
		sleep(ctx, duration)
		if ctx.Err() != nil {
			return op.cancel(ctx)
		}
		opState, err = op.CheckStateAndStatus(ctx)
		duration = nextDuration(duration)
	}
	return err
}

// cancel asks the server to stop the operation once ctx has ended, and returns ctx's error.
// The connection stays usable: no call was abandoned part way (see detachedClient).
func (op *Operation) cancel(ctx context.Context) error {
	op.hive.log.Printf("cancel operation: %v", guid(op.h.OperationId.GUID))
	req := cli_service.TCancelOperationReq{
		OperationHandle: op.h,
	}
	resp, err := op.hive.client.CancelOperation(ctx, &req)
	if err == nil {
		err = checkStatus(resp)
	}
	if err != nil {
		op.hive.log.Printf("cancel operation failed: %v", err)
	}
	return ctx.Err()
}

func fetch(ctx context.Context, op *Operation) (*cli_service.TFetchResultsResp, error) {
	req := cli_service.TFetchResultsReq{
		OperationHandle: op.h,
		MaxRows:         op.hive.opts.MaxRows,
	}

	op.hive.log.Printf("fetch results for operation: %v", guid(op.h.OperationId.GUID))

	var duration time.Duration
	fetchStatus := cli_service.TStatusCode_STILL_EXECUTING_STATUS
	resp := &cli_service.TFetchResultsResp{}
	for fetchStatus == cli_service.TStatusCode_STILL_EXECUTING_STATUS && ctx.Err() == nil {
		// It is questionable if we need to back-off (sleep) in this case
		// impala-shell doesn't - https://github.com/apache/impala/blob/1f35747/shell/impala_client.py#L958
		if duration == 0 {
			duration = initialBackoff
		} else {
			sleep(ctx, duration)
			duration = nextDuration(duration)
		}
		var err error
		resp, err = op.hive.client.FetchResults(ctx, &req)
		if err != nil {
			return nil, err
		}
		if err = checkStatus(resp); err != nil {
			return nil, err
		}
		fetchStatus = resp.GetStatus().StatusCode
	}

	if ctx.Err() != nil {
		return nil, op.cancel(ctx)
	}
	op.hive.log.Printf("results: %v", resp.Results)
	return resp, nil
}

func nextDuration(duration time.Duration) time.Duration {
	duration *= 2
	if duration > maxBackoff {
		duration = maxBackoff
	}
	return duration
}

// Close closes operation and returns rows affected if any
func (op *Operation) Close(ctx context.Context) (int64, error) {
	req := impalaservice.TCloseImpalaOperationReq{
		OperationHandle: op.h,
	}
	resp, err := op.hive.client.CloseImpalaOperation(ctx, &req)
	if err != nil {
		return 0, err
	}
	if err := checkStatus(resp); err != nil {
		return 0, err
	}

	op.hive.log.Printf("close operation: %v", guid(op.h.OperationId.GUID))
	return calcRowsAffected(resp), nil
}

// calcRowsAffected counts the rows a statement changed. An Iceberg UPDATE reports each row twice, once
// written and once as a position delete, and a DELETE reports its rows as deleted alone, so the count is the
// larger of the two.
func calcRowsAffected(resp *impalaservice.TCloseImpalaOperationResp) int64 {
	if resp.DmlResult_ == nil {
		return 0
	}
	var modified, deleted int64
	for _, v := range resp.DmlResult_.GetRowsModified() {
		modified += v
	}
	for _, v := range resp.DmlResult_.GetRowsDeleted() {
		deleted += v
	}
	return max(modified, deleted)
}

// sleep sleeps in a context aware way
func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d): // before Go 1.23, this risked leaking memory but not anymore
	}
}

func getMaxLength(typeQualifiers map[string]*cli_service.TTypeQualifierValue) (int64, bool) {
	lengthQualifier := typeQualifiers["characterMaximumLength"]
	if lengthQualifier == nil {
		return 0, false
	}
	return int64(lengthQualifier.GetI32Value()), true
}

func getPrecisionScale(qualifiers map[string]*cli_service.TTypeQualifierValue) (int64, int64, bool) {
	precisionQ := qualifiers["precision"]
	if precisionQ == nil {
		return 0, 0, false
	}
	scaleQ := qualifiers["scale"]
	if scaleQ == nil {
		return 0, 0, false
	}
	return int64(precisionQ.GetI32Value()), int64(scaleQ.GetI32Value()), true
}
