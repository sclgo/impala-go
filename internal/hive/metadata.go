package hive

import (
	"database/sql"
	"reflect"
	"time"

	"github.com/sclgo/impala-go/internal/generated/cli_service"
)

type TableSchema struct {
	Columns []*ColDesc
}

// ColDesc mirrors sql.ColumnType struct which we can't just reuse because its fields are private
type ColDesc struct {
	Name string

	DatabaseTypeName string
	ScanType         reflect.Type

	// Impala columns are always Nullable, except some Kudu columns
	NotNull bool

	Length    int64
	HasLength bool

	Precision         int64
	Scale             int64
	HasPrecisionScale bool
}

var (
	dataTypeNull     = reflect.TypeOf(nil)
	dataTypeBoolean  = reflect.TypeOf(true)
	dataTypeFloat64  = reflect.TypeOf(float64(0))
	dataTypeInt8     = reflect.TypeOf(int8(0))
	dataTypeInt16    = reflect.TypeOf(int16(0))
	dataTypeInt32    = reflect.TypeOf(int32(0))
	dataTypeInt64    = reflect.TypeOf(int64(0))
	dataTypeString   = reflect.TypeOf("")
	dataTypeDateTime = reflect.TypeOf(time.Time{})
	dataTypeRawBytes = reflect.TypeOf(sql.RawBytes{})
	dataTypeUnknown  = reflect.TypeFor[any]()
)

func typeOf(entry *cli_service.TPrimitiveTypeEntry) reflect.Type {
	switch entry.Type {
	case cli_service.TTypeId_BOOLEAN_TYPE:
		return dataTypeBoolean
	case cli_service.TTypeId_TINYINT_TYPE:
		return dataTypeInt8
	case cli_service.TTypeId_SMALLINT_TYPE:
		return dataTypeInt16
	case cli_service.TTypeId_INT_TYPE:
		return dataTypeInt32
	case cli_service.TTypeId_BIGINT_TYPE:
		return dataTypeInt64
	case cli_service.TTypeId_FLOAT_TYPE, cli_service.TTypeId_DOUBLE_TYPE:
		// see comment in internal/hive/result_set.go#value()
		return dataTypeFloat64
	case cli_service.TTypeId_NULL_TYPE:
		return dataTypeNull
	case cli_service.TTypeId_STRING_TYPE, cli_service.TTypeId_CHAR_TYPE, cli_service.TTypeId_VARCHAR_TYPE:
		return dataTypeString
	case cli_service.TTypeId_DECIMAL_TYPE: // see note in README
		return dataTypeString
	case cli_service.TTypeId_DATE_TYPE, cli_service.TTypeId_TIMESTAMP_TYPE:
		return dataTypeDateTime
	case cli_service.TTypeId_BINARY_TYPE, cli_service.TTypeId_ARRAY_TYPE,
		cli_service.TTypeId_STRUCT_TYPE, cli_service.TTypeId_MAP_TYPE, cli_service.TTypeId_UNION_TYPE:
		return dataTypeRawBytes
	case cli_service.TTypeId_USER_DEFINED_TYPE:
		return dataTypeUnknown
	default:
		return dataTypeUnknown
	}
}
