package hive

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"iter"
	"time"

	"github.com/samber/lo"
	"github.com/sclgo/impala-go/internal/generated/cli_service"
)

type TableName struct {
	Schema string
	Name   string
	Type   string
}

// DBMetadata exposes the database schema. It does not own the underlying client and session
// so they must be open while the objects and the data iterators are used.
type DBMetadata struct {
	h    *cli_service.TSessionHandle
	hive *Client
}

var stringColumn = &ColDesc{
	DatabaseTypeName: "STRING",
}

var tableResultSchema = &TableSchema{
	Columns: []*ColDesc{
		stringColumn,
		stringColumn,
		stringColumn,
		stringColumn,
	},
}

// GetTablesSeq returns tables and views that match the criteria as an iterator. Patterns use LIKE syntax
// Unlike SHOW TABLES IN, GetTablesSeq can work across schemas and can report if the results are tables or views.
func (m DBMetadata) GetTablesSeq(ctx context.Context, schemaPattern string, tableNamePattern string) (iter.Seq[TableName], *error) {
	req := cli_service.TGetTablesReq{
		SessionHandle: m.h,
		SchemaName:    lo.ToPtr(cli_service.TPatternOrIdentifier(schemaPattern)),
		TableName:     lo.ToPtr(cli_service.TPatternOrIdentifier(tableNamePattern)),
	}

	resp, err := m.hive.client.GetTables(ctx, &req)
	if err != nil {
		return nil, &err
	}
	if err = checkStatus(resp); err != nil {
		return nil, &err
	}
	op := &Operation{
		h:    resp.OperationHandle,
		hive: m.hive,
	}

	rs, err := op.FetchResults(ctx, tableResultSchema)
	if err != nil {
		return nil, &err
	}

	return func(yield func(TableName) bool) {
		err = readTables(ctx, op, rs, yield)
	}, &err
}

func readTables(ctx context.Context, op *Operation, rs *ResultSet, yield func(TableName) bool) error {
	row := make([]driver.Value, 4)
	for i := range row {
		row[i] = ""
	}
	var err error
	for err = rs.Next(row); err == nil && ctx.Err() == nil; err = rs.Next(row) {
		tbl := TableName{
			Schema: fmt.Sprintf("%v", row[1]),
			Name:   fmt.Sprintf("%v", row[2]),
			Type:   fmt.Sprintf("%v", row[3]),
		}
		if !yield(tbl) {
			break
		}
	}
	if errors.Is(err, io.EOF) {
		err = nil
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	_ = withFallbackCtx(ctx, op.Close)
	return err
}

// withFallbackCtx ensure cleanup runs even if we are existing because the context is cancelled
func withFallbackCtx(ctx context.Context, cleanup func(ctx context.Context) error) error {
	if ctx.Err() != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
	}
	return cleanup(ctx)
}
