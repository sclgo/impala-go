package impala

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/sclgo/impala-go/hive"
	"github.com/sclgo/impala-go/internal/fi"
	"github.com/stretchr/testify/require"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestIntegration(t *testing.T) {
	fi.SkipLongTest(t)

	dsn := os.Getenv("IMPALA_DSN")
	if dsn == "" {
		ctx := context.Background()
		t.Log("No IMPALA_DSN environment variable set, starting Impala container ...")
		c := fi.NoError(Setup(ctx)).Require(t)
		defer fi.NoErrorF(fi.Bind(c.Terminate, ctx), t)
		dsn = GetDsn(ctx, t, c)
		t.Log("Started impala at url", dsn)
	}

	conn := open(t, dsn)
	defer fi.NoErrorF(conn.Close, t)

	t.Run("Pinger", func(t *testing.T) {
		testPinger(t, conn)
	})
	t.Run("Select", func(t *testing.T) {
		testSelect(t, conn)
	})
	t.Run("Metadata", func(t *testing.T) {
		testMetadata(t, conn)
	})
	t.Run("Insert", func(t *testing.T) {
		testInsert(t, conn)
	})
}

func testPinger(t *testing.T, conn *sql.DB) {
	require.NoError(t, conn.Ping())
}

func testSelect(t *testing.T, db *sql.DB) {
	sampletime, _ := time.Parse(time.RFC3339, "2019-01-01T12:00:00Z")

	tests := []struct {
		sql string
		res interface{}
	}{
		{sql: "1", res: int8(1)},
		{sql: "cast(1 as smallint)", res: int16(1)},
		{sql: "cast(1 as int)", res: int32(1)},
		{sql: "cast(1 as bigint)", res: int64(1)},
		{sql: "cast(1.0 as float)", res: float64(1)},
		{sql: "cast(1.0 as double)", res: float64(1)},
		{sql: "cast(1.0 as real)", res: float64(1)},
		{sql: "'str'", res: "str"},
		{sql: "cast('str' as char(10))", res: "str       "},
		{sql: "cast('str' as varchar(100))", res: "str"},
		{sql: "cast('2019-01-01 12:00:00' as timestamp)", res: sampletime},
	}

	var res interface{}

	for _, tt := range tests {
		t.Run(tt.sql, func(t *testing.T) {
			err := db.QueryRow(fmt.Sprintf("select %s", tt.sql)).Scan(&res)
			require.NoError(t, err)
			require.Equal(t, res, tt.res)
		})
	}
}

func testMetadata(t *testing.T, conn *sql.DB) {
	_, err := conn.Exec("CREATE TABLE IF NOT EXISTS test(a int)")
	require.NoError(t, err)
	m := NewMetadata(conn)
	res, err := m.GetTables(context.Background(), "default", "test")
	require.NoError(t, err)
	require.NotEmpty(t, res)
	require.True(t, slices.ContainsFunc(res, func(tbl hive.TableName) bool {
		return tbl.Name == "test" && tbl.Schema == "default" // && tbl.Type == "TABLE"
	}))
}

func testInsert(t *testing.T, conn *sql.DB) {
	var err error
	_, err = conn.Exec("DROP TABLE IF EXISTS test")
	require.NoError(t, err)
	_, err = conn.Exec("CREATE TABLE if not exists test(a int)")
	require.NoError(t, err)
	insertRes, err := conn.Exec("INSERT INTO test (a) VALUES (1)")
	require.NoError(t, err)
	_, err = insertRes.RowsAffected()
	require.Error(t, err) // not supported yet, see todo in statement.go/exec
	selectRes, err := conn.Query("SELECT * FROM test WHERE a = 1 LIMIT 1")
	require.NoError(t, err)
	defer fi.NoErrorF(selectRes.Close, t)
	require.True(t, selectRes.Next())
	var val int
	require.NoError(t, selectRes.Scan(&val))
	require.Equal(t, val, 1)
}

func open(t *testing.T, dsn string) *sql.DB {
	db, err := sql.Open("impala", dsn)
	if err != nil {
		t.Fatalf("Could not connect to %s: %s", dsn, err)
	}
	return db
}

const dbPort = "21050/tcp"

func Setup(ctx context.Context) (testcontainers.Container, error) {
	req := testcontainers.ContainerRequest{
		Image:        "apache/kudu:impala-latest",
		ExposedPorts: []string{dbPort},
		Cmd:          []string{"impala"},
		WaitingFor:   wait.ForLog("Impala has started.").WithStartupTimeout(3 * time.Minute),
	}
	return testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
}

func GetDsn(ctx context.Context, t *testing.T, c testcontainers.Container) string {
	port := fi.NoError(c.MappedPort(ctx, dbPort)).Require(t).Port()
	host := fi.NoError(c.Host(ctx)).Require(t)
	u := &url.URL{
		Scheme: "impala",
		Host:   net.JoinHostPort(host, port),
		User:   url.User("impala"),
	}
	return u.String()
}
