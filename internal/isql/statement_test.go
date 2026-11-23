package isql

import (
	"database/sql/driver"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBind(t *testing.T) {
	tests := []struct {
		stmt   string
		args   []driver.NamedValue
		target string
	}{
		{
			stmt:   "SELECT ? FROM t -- what?",
			target: "SELECT ? FROM t -- what?",
		},
		{
			stmt:   "@p1 p1",
			args:   []driver.NamedValue{{Ordinal: 1, Value: "val_1"}},
			target: "'val_1' p1",
		},
		{
			stmt: "@p1 @p10 @p11 @named @named1 @p1",
			args: []driver.NamedValue{
				{Ordinal: 1, Value: "val_1"},
				{Ordinal: 10, Name: "named", Value: "val_named"},
				{Ordinal: 11, Value: "val_11"},
			},
			target: "'val_1' @p10 'val_11' 'val_named' @named1 'val_1'",
		},
		{
			stmt:   "@p1 @p2",
			args:   []driver.NamedValue{{Ordinal: 1, Value: "1"}, {Ordinal: 2, Value: int64(2)}},
			target: "'1' 2",
		},
		{
			stmt:   "?",
			args:   []driver.NamedValue{{Ordinal: 1, Value: "O'Brien"}},
			target: `'O\'Brien'`,
		},
		{
			stmt:   "?",
			args:   []driver.NamedValue{{Ordinal: 1, Value: `a\'; DROP TABLE t; --`}},
			target: `'a\\\'; DROP TABLE t; --'`,
		},
		{
			stmt:   "? ?",
			args:   []driver.NamedValue{{Ordinal: 1, Value: "@p2"}, {Ordinal: 2, Value: "x"}},
			target: "'@p2' 'x'",
		},
		{
			stmt:   "value(\"what's my name?\")",
			args:   []driver.NamedValue{{Ordinal: 1, Value: "x"}},
			target: "value(\"what's my name?\")",
		},
		{
			stmt:   "\\? ?",
			args:   []driver.NamedValue{{Ordinal: 1, Value: "x"}},
			target: "\\? 'x'",
		},
		{
			stmt:   "'Hi \\'name\\'?' ?",
			args:   []driver.NamedValue{{Ordinal: 1, Value: "x"}},
			target: "'Hi \\'name\\'?' 'x'",
		},
		{
			stmt: "values('name?', ?, 'age', ?, 'height', ?)",
			args: []driver.NamedValue{
				{Ordinal: 1, Value: "n"},
				{Ordinal: 2, Value: int64(3)},
				{Ordinal: 3, Value: 1.5},
			},
			target: "values('name?', 'n', 'age', 3, 'height', 1.5)",
		},
		{
			stmt:   "values('\"', ?)",
			args:   []driver.NamedValue{{Ordinal: 1, Value: nil}},
			target: "values('\"', NULL)",
		},
		{
			stmt:   "`columnname?` = ?",
			args:   []driver.NamedValue{{Ordinal: 1, Value: true}},
			target: "`columnname?` = TRUE",
		},
		{
			stmt:   "-- it's?\nSELECT ? /* don't? */, ?",
			args:   []driver.NamedValue{{Ordinal: 1, Value: []byte("b")}, {Ordinal: 2, Value: math.Inf(-1)}},
			target: "-- it's?\nSELECT 'b' /* don't? */, CAST('-inf' AS DOUBLE)",
		},
	}

	for _, tt := range tests {
		result, err := bind(tt.stmt, tt.args)
		require.NoError(t, err)
		require.Equal(t, tt.target, result)
	}
}

func TestBind_Negative(t *testing.T) {
	_, err := bind("? ?", []driver.NamedValue{{Ordinal: 1, Value: "x"}})
	require.ErrorIs(t, err, ErrNotSupported)
	_, err = bind("?", []driver.NamedValue{{Ordinal: 1, Value: struct{}{}}})
	require.ErrorIs(t, err, ErrNotSupported)
}
