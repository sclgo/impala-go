package hive

import (
	"database/sql/driver"
	"io"
	"time"

	"github.com/sclgo/impala-go/services/cli_service"
)

// ResultSet ...
type ResultSet struct {
	idx     int
	length  int
	fetchfn func() (*cli_service.TFetchResultsResp, error)
	schema  *TableSchema

	result *cli_service.TRowSet
	more   bool
}

// Next ...
func (rs *ResultSet) Next(dest []driver.Value) error {
	for rs.idx >= rs.length && rs.more {
		// We don't sleep intentionally between loops following the example from impala-shell
		// https://github.com/apache/impala/blob/1f35747/shell/impala_client.py#L958
		resp, err := rs.fetchfn()
		if err != nil {
			return err
		}
		rs.result = resp.Results
		rs.more = resp.GetHasMoreRows()
		rs.idx = 0
		rs.length = length(rs.result)
		// It is possible for rs.more to be true, but length(rs.result) to be 0.
		// This happens when the query is still running but no results were fetched before
		// FETCH_ROWS_TIMEOUT_MS was reached. We keep calling fetchfn in that case
		// until query completes, fails, times out (QUERY_TIMEOUT_MS), or context is cancelled.
	}

	if rs.idx >= rs.length {
		return io.EOF
	}

	for i := range dest {
		val, err := value(rs.result.Columns[i], rs.schema.Columns[i], rs.idx)
		if err != nil {
			return err
		}
		dest[i] = val
	}
	rs.idx++
	return nil
}

func value(col *cli_service.TColumn, cd *ColDesc, i int) (interface{}, error) {
	switch cd.DatabaseTypeName {
	case "STRING", "CHAR", "VARCHAR":
		if col.StringVal.Nulls[i/8]&(1<<(uint(i)%8)) != 0 {
			return nil, nil
		}
		return col.StringVal.Values[i], nil
	case "TINYINT":
		if col.ByteVal.Nulls[i/8]&(1<<(uint(i)%8)) != 0 {
			return nil, nil
		}
		return col.ByteVal.Values[i], nil
	case "SMALLINT":
		if col.I16Val.Nulls[i/8]&(1<<(uint(i)%8)) != 0 {
			return nil, nil
		}
		return col.I16Val.Values[i], nil
	case "INT":
		if col.I32Val.Nulls[i/8]&(1<<(uint(i)%8)) != 0 {
			return nil, nil
		}
		return col.I32Val.Values[i], nil
	case "BIGINT":
		if col.I64Val.Nulls[i/8]&(1<<(uint(i)%8)) != 0 {
			return nil, nil
		}
		return col.I64Val.Values[i], nil
	case "BOOLEAN":
		if col.BoolVal.Nulls[i/8]&(1<<(uint(i)%8)) != 0 {
			return nil, nil
		}
		return col.BoolVal.Values[i], nil
	case "FLOAT", "DOUBLE":
		if col.DoubleVal.Nulls[i/8]&(1<<(uint(i)%8)) != 0 {
			return nil, nil
		}
		return col.DoubleVal.Values[i], nil
	case "TIMESTAMP", "DATETIME":
		if col.StringVal.Nulls[i/8]&(1<<(uint(i)%8)) != 0 {
			return nil, nil
		}
		t, err := time.Parse(TimestampFormat, col.StringVal.Values[i])
		if err != nil {
			return nil, err
		}
		return t, nil
	default:
		if col.StringVal.Nulls[i/8]&(1<<(uint(i)%8)) != 0 {
			return nil, nil
		}
		return col.StringVal.Values[i], nil
	}
}

func length(rs *cli_service.TRowSet) int {
	if rs == nil {
		return 0
	}
	for _, col := range rs.Columns {
		if col.BoolVal != nil {
			return len(col.BoolVal.Values)
		}
		if col.ByteVal != nil {
			return len(col.ByteVal.Values)
		}
		if col.I16Val != nil {
			return len(col.I16Val.Values)
		}
		if col.I32Val != nil {
			return len(col.I32Val.Values)
		}
		if col.I32Val != nil {
			return len(col.I32Val.Values)
		}
		if col.I64Val != nil {
			return len(col.I64Val.Values)
		}
		if col.StringVal != nil {
			return len(col.StringVal.Values)
		}
		if col.DoubleVal != nil {
			return len(col.DoubleVal.Values)
		}
	}
	return 0
}
