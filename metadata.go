package impala

import (
	"context"
	"database/sql"
	"errors"
	"iter"
	"slices"

	"github.com/sclgo/impala-go/internal/hive"
	"github.com/sclgo/impala-go/internal/isql"
)

// Metadata exposes the schema and other metadata in an Impala instance
type Metadata struct {
	db   *sql.DB
	conn ConnRawAccess
}

// ConnRawAccess exposes the Raw method of sql.Conn
type ConnRawAccess interface {
	Raw(func(driverConn any) error) error
}

// TableName contains all attributes that identify a table
type TableName = hive.TableName

// ColumnName contains all attributes that identify a columns
type ColumnName = hive.ColumnName

// It is questionable if it is appropriate to have a type alias to internal package
// in a public package. Will change if it becomes an issue.

// NewMetadata creates Metadata instance with the given Impala DB as data source. A new connection
// will be retrieved for any call. If that's an issue, use NewMetadataFromConn
func NewMetadata(db *sql.DB) *Metadata {
	return &Metadata{db: db}
}

// NewMetadataFromConn creates Metadata instance with the given Impala connection as data source
// *sql.Conn implements ConnRawAccess
func NewMetadataFromConn(conn ConnRawAccess) *Metadata {
	return &Metadata{conn: conn}
}

// GetColumns retrieves columns that match the provided LIKE patterns
func (m Metadata) GetColumns(ctx context.Context, schemaPattern string, tableNamePattern string, columnNamePattern string) ([]ColumnName, error) {
	return raw(ctx, m.db, m.conn, func(dbm hive.DBMetadata) (iter.Seq[hive.ColumnName], *error) {
		return dbm.GetColumnsSeq(ctx, schemaPattern, tableNamePattern, columnNamePattern)
	})
}

// GetTables retrieves tables and views that match the provided LIKE patterns
func (m Metadata) GetTables(ctx context.Context, schemaPattern string, tableNamePattern string) ([]TableName, error) {
	return raw(ctx, m.db, m.conn, func(dbm hive.DBMetadata) (iter.Seq[hive.TableName], *error) {
		return dbm.GetTablesSeq(ctx, schemaPattern, tableNamePattern)
	})
}

// GetSchemas retrieves schemas that match the provided LIKE pattern
func (m Metadata) GetSchemas(ctx context.Context, schemaPattern string) ([]string, error) {
	return raw(ctx, m.db, m.conn, func(dbm hive.DBMetadata) (iter.Seq[string], *error) {
		return dbm.GetSchemasSeq(ctx, schemaPattern)
	})
}

// raw executes the given sequence-producing function over a HiveSession derived from a raw connection produced by db
func raw[T any](ctx context.Context, db *sql.DB, dbconn ConnRawAccess, f func(hive.DBMetadata) (iter.Seq[T], *error)) ([]T, error) {
	var res []T
	var err error
	if dbconn == nil {
		var conn *sql.Conn
		conn, err = db.Conn(ctx)
		if err != nil {
			return res, err
		}
		defer func() {
			err = conn.Close()
		}()
		dbconn = conn
	}

	res, err = execOnRaw(ctx, dbconn, f)
	return res, err // err may be overwritten in defer
}

func execOnRaw[T any](ctx context.Context, conn ConnRawAccess, f func(hive.DBMetadata) (iter.Seq[T], *error)) ([]T, error) {
	var res []T
	err := conn.Raw(func(driverConn any) error {
		impalaConn, ok := driverConn.(*isql.Conn)
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
		// driverConn might not be valid outside this method so we can't return anything
		// that depends on it like the iterator itself
		res = slices.Collect(resIter)
		return *funcErr
	})
	return res, err
}
