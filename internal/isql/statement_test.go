package isql

import (
	"database/sql/driver"
	"testing"
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

		if result != tt.target {
			t.Fatalf("mismatch for statement: %q\n\ttarget: %q\n\tresult: %q", tt.stmt, tt.target, result)
		}
	}
}
