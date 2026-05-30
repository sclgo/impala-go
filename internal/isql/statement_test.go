package isql

import (
	"database/sql/driver"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStatement_ValueReplacement(t *testing.T) {
	tests := []struct {
		stmt   string
		args   []driver.NamedValue
		target string
	}{
		{
			stmt: "@p1 p1",
			args: []driver.NamedValue{
				driver.NamedValue{Ordinal: 1, Value: "val_1"},
			},
			target: "'val_1' p1",
		},
		{
			stmt: "@p1 @p10 @p11 @named @named1 @p1",
			args: []driver.NamedValue{
				driver.NamedValue{Ordinal: 1, Value: "val_1"},
				driver.NamedValue{Ordinal: 10, Name: "named", Value: "val_named"},
				driver.NamedValue{Ordinal: 11, Value: "val_11"},
			},
			target: "'val_1' @p10 'val_11' 'val_named' @named1 'val_1'",
		},
		{
			stmt: "@p1 @p2",
			args: []driver.NamedValue{
				driver.NamedValue{Ordinal: 1, Value: "1"},
				driver.NamedValue{Ordinal: 2, Value: 2},
			},
			target: "'1' 2",
		},
	}

	for _, tt := range tests {
		result := statement(tt.stmt, tt.args)
		require.Equal(t, tt.target, result)
	}
}

func TestTemplate(t *testing.T) {
	tests := []struct {
		stmt   string
		target string
	}{
		{
			stmt:   "?",
			target: "@p1",
		},
		{
			stmt:   "value(\"what's my name?\")",
			target: "value(\"what's my name?\")",
		},
		{
			stmt:   "\\?",
			target: "\\?",
		},
		{
			stmt:   "'Hi \\'name\\'?'",
			target: "'Hi \\'name\\'?'",
		},
		{
			stmt:   "values('name?', ?, 'age', ?, 'height', ?)",
			target: "values('name?', @p1, 'age', @p2, 'height', @p3)",
		},
		{
			stmt:   "values('\"', ?)",
			target: "values('\"', @p1)",
		},
		{
			stmt:   "`columnname?`",
			target: "`columnname?`",
		},
	}

	for _, tt := range tests {
		result := template(tt.stmt)
		require.Equal(t, tt.target, result)
	}
}
