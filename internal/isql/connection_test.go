package isql_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"net"
	"net/url"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/samber/lo"
	"github.com/sclgo/impala-go"
	"github.com/sclgo/impala-go/internal/fi"
	"github.com/sclgo/impala-go/internal/sclerr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tc "github.com/testcontainers/testcontainers-go/modules/compose"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestIntegration_FromEnv(t *testing.T) {
	fi.SkipLongTest(t)

	dsn := os.Getenv("IMPALA_DSN")
	if dsn == "" {
		t.Skip("No IMPALA_DSN environment variable set. Skipping this test ...")
	}

	runSuite(t, dsn)
}

func TestIntegration_Impala3(t *testing.T) {
	fi.SkipLongTest(t)
	dsn := startImpala(t)
	runSuite(t, dsn)
}

func TestIntegration_Impala4(t *testing.T) {
	fi.SkipLongTest(t)
	dsn := startImpala4(t)
	runSuite(t, dsn)
	runImpala4SpecificTests(t, dsn)
}

func TestIntegration_Restart(t *testing.T) {
	fi.SkipLongTest(t)
	// TODO This test is slow and can be optimized by using the Impala 4 multi-container setup
	// Restarting only impalad will be much faster than restarting the entire stack
	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "apache/kudu:impala-latest",
		ExposedPorts: []string{"21050:21050"}, // TODO random port that is stable across restart
		Cmd:          []string{"impala"},
		WaitingFor:   waitRule,
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})

	require.NoError(t, err)
	dsn := GetDsn(ctx, t, c)
	t.Cleanup(func() {
		err := c.Terminate(ctx)
		assert.NoError(t, err)
	})

	db := fi.NoError(sql.Open("impala", dsn)).Require(t)
	defer sclerr.CloseQuietly(db)

	conn, err := db.Conn(ctx)
	require.NoError(t, err)

	defer sclerr.CloseQuietly(conn)

	err = conn.PingContext(ctx)
	require.NoError(t, err)

	// ensure there is an open connection in the pool
	err = db.PingContext(ctx)
	require.NoError(t, err)

	err = c.Stop(ctx, lo.ToPtr(1*time.Minute))
	require.NoError(t, err)
	err = c.Start(ctx)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		perr := db.PingContext(ctx)
		if perr != nil {
			require.ErrorIs(t, perr, driver.ErrBadConn)
		}
		t.Log(perr)
		return perr == nil
	}, 2*time.Minute, 2*time.Second)

	err = conn.PingContext(ctx)
	require.Error(t, err)
	// require.ErrorIs(t, err, driver.ErrBadConn) hmmm?
}

func runSuite(t *testing.T, dsn string) {
	db := fi.NoError(sql.Open("impala", dsn)).Require(t)
	defer fi.NoErrorF(db.Close, t)

	t.Run("happy", func(t *testing.T) {
		runHappyCases(t, db)
	})
	t.Run("error", func(t *testing.T) {
		runErrorCases(t, db)
	})
}

func runHappyCases(t *testing.T, db *sql.DB) {
	t.Run("Pinger", func(t *testing.T) {
		testPinger(t, db)
	})
	t.Run("Select", func(t *testing.T) {
		testSelect(t, db)
	})
	t.Run("Metadata", func(t *testing.T) {
		testMetadata(t, db)
	})
	t.Run("Insert", func(t *testing.T) {
		testInsert(t, db)
	})
}

func runErrorCases(t *testing.T, db *sql.DB) {
	t.Run("DDL fails in HMS", func(t *testing.T) {
		var err error
		_, err = db.Exec("DROP TABLE IF EXISTS test")
		require.NoError(t, err)
		// HMS reports that non-external tables LOCATION must be under the warehouse root
		// (or, in some versions, that /some/location doesn't exist.
		// Impala handles oddly errors which it didn't detect but were reported by HMS:
		// status is SUCCESS, but state is ERROR
		_, err = db.Exec("CREATE TABLE test(a int) LOCATION '/some/location'")
		require.ErrorContains(t, err, "ImpalaRuntimeException")
	})
}

func runImpala4SpecificTests(t *testing.T, dsn string) {
	db := fi.NoError(sql.Open("impala", dsn)).Require(t)
	defer fi.NoErrorF(db.Close, t)

	t.Run("DDL fails in HMS unexpectedly", func(t *testing.T) {
		var err error
		_, err = db.Exec("DROP TABLE IF EXISTS test")
		require.NoError(t, err)
		// s3 locations fails in quickstart hive metastore image because it doesn't
		// include the jars for s3 support. The test confirms the
		// driver handles this unusual error without locking up.
		// We need to use a real public bucket because Impala validates it before passing it to Hive.
		_, err = db.Exec("CREATE EXTERNAL TABLE test(a int) LOCATION 's3a://daylight-openstreetmap/earth'")
		require.ErrorContains(t, err, "ClassNotFoundException")
	})
}

func startImpala(t *testing.T) string {
	ctx := context.Background()
	c := fi.NoError(Setup(ctx)).Require(t)
	dsn := GetDsn(ctx, t, c)
	t.Cleanup(func() {
		err := c.Terminate(ctx)
		assert.NoError(t, err)
	})
	return dsn
}

func startImpala4(t *testing.T) string {
	var compose tc.ComposeStack
	compose, err := tc.NewDockerCompose("../../compose/quickstart.yml")
	require.NoError(t, err)
	compose = compose.WithEnv(map[string]string{
		"IMPALA_QUICKSTART_IMAGE_PREFIX": "apache/impala:4.4.1-",
		"QUICKSTART_LISTEN_ADDR":         "0.0.0.0",
	})
	t.Cleanup(func() {
		assert.NoError(t, compose.Down(context.Background(), tc.RemoveOrphans(true)))
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	require.NoError(t, compose.WaitForService("impalad-1", waitRule).Up(ctx, tc.Wait(true)))
	c, err := compose.ServiceContainer(ctx, "impalad-1")
	require.NoError(t, err)
	return GetDsn(ctx, t, c)
}

func testPinger(t *testing.T, db *sql.DB) {
	require.NoError(t, db.Ping())
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
		// confirms that fetch 0 rows with hasMoreRows = true is correctly handled
		// relies on FETCH_ROWS_TIMEOUT_MS="1000", configured below
		{sql: "sleep(2000)", res: true},
	}

	var res interface{}

	ctx := context.Background()
	conn, err := db.Conn(ctx)
	require.NoError(t, err)
	defer fi.NoErrorF(conn.Close, t)
	_, err = conn.ExecContext(ctx, `SET FETCH_ROWS_TIMEOUT_MS="1000"`)
	require.NoError(t, err)
	for _, tt := range tests {
		t.Run(tt.sql, func(t *testing.T) {
			err = conn.QueryRowContext(ctx, fmt.Sprintf("select %s", tt.sql)).Scan(&res)
			require.NoError(t, err)
			require.Equal(t, tt.res, res)
		})
	}
}

func testMetadata(t *testing.T, conn *sql.DB) {
	// We don't drop test if it exists because the tests doesn't care (for now) if the table has different columns
	_, cerr := conn.Exec("CREATE TABLE IF NOT EXISTS test(a int)")
	require.NoError(t, cerr)
	m := impala.NewMetadata(conn)
	t.Run("Tables", func(t *testing.T) {
		res, err := m.GetTables(context.Background(), "defaul%", "tes%")
		require.NoError(t, err)
		require.NotEmpty(t, res)
		require.True(t, slices.ContainsFunc(res, func(tbl impala.TableName) bool {
			return tbl.Name == "test" && tbl.Schema == "default" && tbl.Type == "TABLE"
		}))
	})
	t.Run("Schemas", func(t *testing.T) {
		res, err := m.GetSchemas(context.Background(), "defaul%")
		require.NoError(t, err)
		require.Contains(t, res, "default")
	})

}

func testInsert(t *testing.T, conn *sql.DB) {
	var err error
	_, err = conn.Exec("DROP TABLE IF EXISTS test")
	require.NoError(t, err)
	_, err = conn.Exec("CREATE TABLE test(a int)")
	require.NoError(t, err)
	insertRes, err := conn.Exec("INSERT INTO test (a) VALUES (?)", 1)
	require.NoError(t, err)
	_, err = insertRes.RowsAffected()
	require.Error(t, err) // not supported yet, see todo in statement.go/exec
	selectRes, err := conn.Query("SELECT * FROM test WHERE a = ? LIMIT 1", 1)
	require.NoError(t, err)
	defer fi.NoErrorF(selectRes.Close, t)
	require.True(t, selectRes.Next())
	var val int
	require.NoError(t, selectRes.Scan(&val))
	require.Equal(t, val, 1)
}

const dbPort = "21050/tcp"

var waitRule = wait.ForLog("Impala has started.").WithStartupTimeout(3 * time.Minute)

func Setup(ctx context.Context) (testcontainers.Container, error) {

	req := testcontainers.ContainerRequest{
		Image:        "apache/kudu:impala-latest",
		ExposedPorts: []string{dbPort},
		Cmd:          []string{"impala"},
		WaitingFor:   waitRule,
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
		Scheme:   "impala",
		Host:     net.JoinHostPort(host, port),
		User:     url.User("impala"),
		RawQuery: "log=stderr",
	}
	return u.String()
}
