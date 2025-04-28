package isql

import (
	"database/sql/driver"
	"reflect"

	"github.com/sclgo/impala-go/internal/hive"
)

// Rows is an iterator over an executed query's results.
type Rows struct {
	rs      *hive.ResultSet
	schema  *hive.TableSchema
	closefn func() error
}

// Close closes rows iterator. Implements [driver.Rows].
func (r *Rows) Close() error {
	return r.closefn()
}

// Columns returns the names of the columns. Implements [driver.Rows].
func (r *Rows) Columns() []string {
	var cols []string
	for _, col := range r.schema.Columns {
		cols = append(cols, col.Name)
	}
	return cols
}

// ColumnTypeScanType returns column's native type.
// Implements [driver.RowsColumnTypeScanType]
func (r *Rows) ColumnTypeScanType(index int) reflect.Type {
	return r.schema.Columns[index].ScanType
}

// ColumnTypeDatabaseTypeName returns column's database type name.
// Implements [driver.RowsColumnTypeDatabaseTypeName]
func (r *Rows) ColumnTypeDatabaseTypeName(index int) string {
	return r.schema.Columns[index].DatabaseTypeName
}

// ColumnTypeNullable implements [driver.RowsColumnTypeNullable]
func (r *Rows) ColumnTypeNullable(index int) (nullable, ok bool) {
	return !r.schema.Columns[index].NotNull, true
}

// ColumnTypePrecisionScale implements [driver.RowsColumnTypePrecisionScale]
func (r *Rows) ColumnTypePrecisionScale(index int) (precision, scale int64, ok bool) {
	colDesc := r.schema.Columns[index]
	return colDesc.Precision, colDesc.Scale, colDesc.HasPrecisionScale
}

// ColumnTypeLength implements [driver.RowsColumnTypeLength]
func (r *Rows) ColumnTypeLength(index int) (length int64, ok bool) {
	colDesc := r.schema.Columns[index]
	return colDesc.Length, colDesc.HasLength
}

// Next prepares next row for scanning. Implements [driver.Rows].
func (r *Rows) Next(dest []driver.Value) error {
	return r.rs.Next(dest)
}
