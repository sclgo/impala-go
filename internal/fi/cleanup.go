package fi

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Helpers for t.Cleanup

func CleanupF(t *testing.T, f func() error) {
	t.Cleanup(func() {
		assert.NoError(t, f())
	})
}
