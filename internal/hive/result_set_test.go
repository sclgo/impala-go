package hive

import (
	"database/sql/driver"
	"fmt"
	"io"
	"testing"

	"github.com/samber/lo"
	"github.com/sclgo/impala-go/internal/generated/cli_service"
	"github.com/stretchr/testify/require"
)

func TestResultSet(t *testing.T) {
	t.Run("fetch 0 but has more", func(t *testing.T) {
		r := &results{
			data: []any{
				[]*cli_service.TColumn{},
				[]*cli_service.TColumn{
					{
						StringVal: &cli_service.TStringColumn{
							Nulls:  []byte{0},
							Values: []string{"hello"},
						},
					},
				},
			},
		}
		rs := ResultSet{
			idx:     0,
			length:  0,
			fetchfn: r.fetch,
			more:    true,
			schema: &TableSchema{
				Columns: []*ColDesc{
					{
						DatabaseTypeName: "VARCHAR",
					},
				},
			},
		}
		data := make([]driver.Value, 1)
		err := rs.Next(data)
		require.NoError(t, err)
		require.EqualValues(t, "hello", data[0])
		err = rs.Next(data)
		require.Equal(t, io.EOF, err)
	})
}

type results struct {
	idx  int
	data []any
}

func (r *results) fetch() (*cli_service.TFetchResultsResp, error) {
	dataPoint := r.data[r.idx]
	r.idx++
	switch d := dataPoint.(type) {
	case error:
		return nil, d
	case *cli_service.TFetchResultsResp:
		return d, nil
	case []*cli_service.TColumn:
		return &cli_service.TFetchResultsResp{
			Status:      &cli_service.TStatus{},
			HasMoreRows: lo.ToPtr(r.idx < len(r.data)),
			Results: &cli_service.TRowSet{
				StartRowOffset: int64(r.idx - 1),
				Columns:        d,
			},
		}, nil
	default:
		panic(fmt.Sprintf("unexpected data type: %T", dataPoint))
	}

}
