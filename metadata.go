package impala

import (
	"context"
	"database/sql"
	"errors"
	"iter"
	"slices"

	"github.com/sclgo/impala-go/hive"
)

// Metadata implements simplified access to hive.DBMetadata given only a high-level sql.DB reference
// Since we use internally sql.Conn.Raw, we can't return iterators but only full slices.
type Metadata struct {
	db *sql.DB
}

func NewMetadata(db *sql.DB) *Metadata {
	return &Metadata{db: db}
}

// GetTables returns tables and views in the same way as the underlying method in hive.DBMetadata
func (m Metadata) GetTables(ctx context.Context, schemaPattern string, tableNamePattern string) ([]hive.TableName, error) {
	return raw(ctx, m.db, func(dbm hive.DBMetadata) (iter.Seq[hive.TableName], *error) {
		return dbm.GetTablesSeq(ctx, schemaPattern, tableNamePattern)
	})
}

// raw executes the given sequence-producing function over a HiveSession derived from a raw connection produced by db
func raw[T any](ctx context.Context, db *sql.DB, f func(hive.DBMetadata) (iter.Seq[T], *error)) ([]T, error) {
	var res []T
	conn, err := db.Conn(ctx)
	if err != nil {
		return res, err
	}
	defer func() {
		err = conn.Close()
	}()
	err = conn.Raw(func(driverConn any) error {
		impalaConn, ok := driverConn.(*Conn)
		if !ok {
			return errors.New("metadata can operate only on Impala drivers")
		}
		session, sessionErr := impalaConn.OpenSession(ctx)
		if sessionErr != nil {
			return sessionErr
		}
		dbm := session.DBMetadata()
		resIter, funcErr := f(dbm)
		if *funcErr != nil {
			return *funcErr
		}
		// Since, given Conn.Raw spec, the raw connection is valid only within this function,
		// we fully consume the iterator and don't let it escape.
		res = slices.Collect(resIter)
		return *funcErr
	})
	if err != nil {
		return res, err
	}
	return res, err
}
