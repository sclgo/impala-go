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

type ColumnName struct {
	Schema     string
	TableName  string
	ColumnName string
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

func (m DBMetadata) GetColumnsSeq(ctx context.Context, schemaPattern string, tableNamePattern string, columnNamePattern string) (iter.Seq[ColumnName], *error) {
	req := cli_service.TGetColumnsReq{
		SessionHandle: m.h,
		SchemaName:    lo.ToPtr(cli_service.TPatternOrIdentifier(schemaPattern)),
		TableName:     lo.ToPtr(cli_service.TPatternOrIdentifier(tableNamePattern)),
		ColumnName:    lo.ToPtr(cli_service.TPatternOrIdentifier(columnNamePattern)),
	}

	resp, err := m.hive.client.GetColumns(ctx, &req)
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

	return func(yield func(name ColumnName) bool) {
		err = read(ctx, op, rs, 4, readColumn, yield)
	}, &err
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
		err = read(ctx, op, rs, 4, readTable, yield)
	}, &err
}

func (m DBMetadata) GetSchemasSeq(ctx context.Context, pattern string) (iter.Seq[string], *error) {
	req := cli_service.TGetSchemasReq{
		SessionHandle: m.h,
		SchemaName:    lo.ToPtr(cli_service.TPatternOrIdentifier(pattern)),
	}

	resp, err := m.hive.client.GetSchemas(ctx, &req)
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

	return func(yield func(string) bool) {
		err = read(ctx, op, rs, 1, readSchema, yield)
	}, &err
}

func read[T any](ctx context.Context, op *Operation, rs *ResultSet, rowLength int, readf func([]driver.Value) T, yield func(T) bool) error {
	row := make([]driver.Value, rowLength)
	for i := range row {
		row[i] = ""
	}
	var err error
	for err = rs.Next(row); err == nil && ctx.Err() == nil; err = rs.Next(row) {
		tbl := readf(row)
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
	_ = withFallbackCtx(ctx, func(ctx context.Context) error {
		_, err := op.Close(ctx)
		return err
	})
	return err
}

func readTable(row []driver.Value) TableName {
	return TableName{
		Schema: fmt.Sprintf("%v", row[1]),
		Name:   fmt.Sprintf("%v", row[2]),
		Type:   fmt.Sprintf("%v", row[3]),
	}
}

func readColumn(row []driver.Value) ColumnName {
	return ColumnName{
		Schema:     fmt.Sprintf("%v", row[1]),
		TableName:  fmt.Sprintf("%v", row[2]),
		ColumnName: fmt.Sprintf("%v", row[3]),
		// There is no column 4
	}
}

func readSchema(row []driver.Value) string {
	return fmt.Sprintf("%v", row[0])
}

// withFallbackCtx ensure cleanup runs even if we are cleaning up because the context is cancelled
func withFallbackCtx(ctx context.Context, cleanup func(ctx context.Context) error) error {
	if ctx.Err() != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
	}
	return cleanup(ctx)
}
