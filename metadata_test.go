package impala_test

import (
	"context"
	"testing"

	"github.com/sclgo/impala-go"
	"github.com/stretchr/testify/require"
)

// This file contains only unit tests for metadata.go.
// Integration tests, which provide the majority of test coverage, are in connection_test.go
// to reuse Impala test instance setup there.

type myConn struct {
	rawConn any
}

func (m myConn) Raw(f func(driverConn any) error) error {
	return f(m.rawConn)
}

func TestMetadata_GetTables(t *testing.T) {
	t.Run("raw conn is not impala", func(t *testing.T) {
		meta := impala.NewMetadataFromConn(myConn{1})
		_, err := meta.GetTables(context.Background(), "", "")
		require.Error(t, err)
	})
}
