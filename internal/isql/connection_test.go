package isql_test

// Integration tests for driver
// Create or update connection_int_test.go to add unit tests

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/docker/docker/api/types/volume"
	"github.com/samber/lo"
	"github.com/sclgo/impala-go"
	"github.com/sclgo/impala-go/internal/fi"
	"github.com/sclgo/impala-go/internal/sclerr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
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

// TestIntegration_Impala3 covers integration with Impala 3.x and no TLS - plain TCP
func TestIntegration_Impala3(t *testing.T) {
	fi.SkipLongTest(t)
	dsn := startImpala3(t)
	runSuite(t, dsn)
}

// TestIntegration_Impala4 covers integration with Impala 4.x and TLS
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
	dsn := getDsn(ctx, t, c)
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
	t.Run("Connection State", func(t *testing.T) {
		testConnState(t, db)
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

	t.Run("Context Cancelled", func(t *testing.T) {

		startTime := time.Now()
		bkgCtx := context.Background()
		conn, err := db.Conn(bkgCtx)
		require.NoError(t, err)
		defer fi.NoErrorF(conn.Close, t)
		_, err = conn.ExecContext(bkgCtx, `SET FETCH_ROWS_TIMEOUT_MS="500"`)
		require.NoError(t, err)
		ctx, cancel := context.WithTimeout(bkgCtx, 1*time.Second)
		defer cancel()
		row := conn.QueryRowContext(ctx, "SELECT SLEEP(10000)")
		var val any
		err = row.Scan(&val)
		require.NoError(t, row.Err())
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.Less(t, time.Since(startTime), 5*time.Second)

	})
}

// testConnState verifies that the connection created db.Conn matches 1:1
// to an Impala connection so connection-scoped state persists across calls
func testConnState(t *testing.T, db *sql.DB) {
	var err error
	_, err = db.Exec("CREATE DATABASE IF NOT EXISTS foo")
	require.NoError(t, err)
	_, err = db.Exec("DROP TABLE IF EXISTS foo.bar")
	require.NoError(t, err)
	_, err = db.Exec("CREATE TABLE foo.bar(a int)")
	require.NoError(t, err)
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	require.NoError(t, err)
	defer fi.NoErrorF(conn.Close, t)
	_, err = conn.ExecContext(ctx, "USE foo")
	require.NoError(t, err)
	res, err := conn.QueryContext(ctx, "SELECT * FROM bar")
	require.NoError(t, err)
	require.NoError(t, res.Close())
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

func startImpala3(t *testing.T) string {
	ctx := context.Background()
	c := fi.NoError(Setup(ctx)).Require(t)
	dsn := getDsn(ctx, t, c)
	t.Cleanup(func() {
		err := c.Terminate(ctx)
		assert.NoError(t, err)
	})
	return dsn
}

func startImpala4(t *testing.T) string {
	ctx := context.Background()
	c := setupStack(ctx, t)
	dsn := getDsn(ctx, t, c)
	certPath := filepath.Join("..", "..", "compose", "testssl", "localhost.crt")
	dsn += "&tls=true&ca-cert=" + fi.NoError(filepath.Abs(certPath)).Require(t)
	return dsn
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

func toCloser(ct testcontainers.Container) func() error {
	return func() error {
		return ct.Terminate(context.Background())
	}
}

func setupStack(ctx context.Context, t *testing.T) testcontainers.Container {
	//nolint:staticcheck - deprecated but alternative doesn't allow customizing name; default name is invalid
	netReq := testcontainers.NetworkRequest{
		Driver: "bridge",
		Name:   "quickstart-network",
	}

	//nolint:staticcheck - deprecated see above
	containerNet, err := testcontainers.GenericNetwork(ctx, testcontainers.GenericNetworkRequest{
		NetworkRequest: netReq,
	})
	require.NoError(t, err)
	fi.CleanupF(t, fi.Bind(containerNet.Remove, context.Background()))

	docker, err := testcontainers.NewDockerClientWithOpts(ctx)
	require.NoError(t, err)
	warehouseVol, err := docker.VolumeCreate(ctx, volume.CreateOptions{
		Name: "impala-quickstart-warehouse",
	})
	require.NoError(t, err)
	fi.CleanupF(t, func() error {
		return docker.VolumeRemove(context.Background(), warehouseVol.Name, true)
	})
	warehouseMount := testcontainers.VolumeMount(warehouseVol.Name, "/user/hive/warehouse")
	localHiveSite := fi.NoError(filepath.Abs("../../compose/quickstart_conf/hive-site.xml")).Require(t)

	req := testcontainers.ContainerRequest{
		Image:    "apache/impala:4.4.1-impala_quickstart_hms",
		Cmd:      []string{"hms"},
		Networks: []string{netReq.Name},
		Mounts: testcontainers.ContainerMounts{
			warehouseMount,
			testcontainers.VolumeMount(warehouseVol.Name, "/var/lib/hive"),
		},
		Binds: []string{
			localHiveSite + ":" + "/opt/hive/conf/hive-site.xml",
		},
		Name:       "quickstart-hive-metastore",
		WaitingFor: wait.ForLog("Starting Hive Metastore Server"),
	}
	ct, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)
	fi.CleanupF(t, toCloser(ct))

	req = testcontainers.ContainerRequest{
		Image: "apache/impala:4.4.1-statestored",
		Cmd: []string{
			"-redirect_stdout_stderr=false",
			"-logtostderr",
			"-v=1",
		},
		Networks: []string{netReq.Name},
		Binds: []string{
			// we use this deprecated field, because the alternative is much harder to use.
			localHiveSite + ":" + "/opt/impala/conf/hive-site.xml",
		},
		Name:       "statestored",
		WaitingFor: wait.ForLog("ThriftServer 'StatestoreService' started"),
	}
	ct, err = testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)
	fi.CleanupF(t, toCloser(ct))

	req = testcontainers.ContainerRequest{
		Image: "apache/impala:4.4.1-catalogd",
		Cmd: []string{
			"-redirect_stdout_stderr=false",
			"-logtostderr",
			"-v=1",
			"-hms_event_polling_interval_s=1",
			"-invalidate_tables_timeout_s=999999",
		},
		Networks: []string{netReq.Name},
		Binds: []string{
			localHiveSite + ":" + "/opt/impala/conf/hive-site.xml",
		},
		Mounts: testcontainers.ContainerMounts{
			warehouseMount,
		},
		Name: "catalogd",
	}
	ct, err = testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)
	fi.CleanupF(t, toCloser(ct))

	req = testcontainers.ContainerRequest{
		Image: "apache/impala:4.4.1-impalad_coord_exec",
		Cmd: []string{
			"-v=1",
			"-redirect_stdout_stderr=false",
			"-logtostderr",
			"-kudu_master_hosts=kudu-master-1:7051",
			"-mt_dop_auto_fallback=true",
			"-default_query_options=mt_dop=4,default_file_format=parquet,default_transactional_type=insert_only",
			"-mem_limit=4gb",
			"-ssl_server_certificate=/ssl/localhost.crt",
			"-ssl_private_key=/ssl/localhost.key",
		},
		Networks: []string{netReq.Name},
		Binds: []string{
			localHiveSite + ":" + "/opt/impala/conf/hive-site.xml",
			fi.NoError(filepath.Abs("../../compose/testssl")).Require(t) + ":" + "/ssl",
		},
		WaitingFor: waitRule,
		Mounts: testcontainers.ContainerMounts{
			warehouseMount,
		},
		Env: map[string]string{
			"JAVA_TOOL_OPTIONS": "-Xmx1g",
		},
		ExposedPorts: []string{dbPort},
		Name:         "impalad",
	}
	ct, err = testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)
	fi.CleanupF(t, toCloser(ct))

	return ct
}

func getDsn(ctx context.Context, t *testing.T, c testcontainers.Container) string {
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
