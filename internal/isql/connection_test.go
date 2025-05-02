package isql_test

// Integration tests for driver
// Create or update connection_int_test.go to add unit tests

import (
	"context"
	"crypto/tls"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/volume"
	"github.com/docker/go-units"
	"github.com/murfffi/gorich/fi"
	"github.com/murfffi/gorich/helperr"
	"github.com/murfffi/gorich/lang"
	"github.com/samber/lo"
	"github.com/sclgo/impala-go"
	"github.com/sclgo/impala-go/internal/hive"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	impala4User = url.UserPassword("fry", "fry")
)

func init() {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()
}

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
	dsn := getDsn(ctx, t, c, nil)
	t.Cleanup(func() {
		err := c.Terminate(ctx)
		assert.NoError(t, err)
	})

	db := fi.NoError(sql.Open("impala", dsn)).Require(t)
	defer helperr.CloseQuietly(db)

	conn, err := db.Conn(ctx)
	require.NoError(t, err)

	defer helperr.CloseQuietly(conn)

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
	t.Run("SelectOneIntoAny", func(t *testing.T) {
		testSelectOneIntoAny(t, db)
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

	t.Run("built-in certs", func(t *testing.T) {
		noCertsDsnUrl, err := url.Parse(dsn)
		require.NoError(t, err)
		query := noCertsDsnUrl.Query()
		query.Del("ca-cert")
		noCertsDsnUrl.RawQuery = query.Encode()
		builtInCertsDb := fi.NoError(sql.Open("impala", noCertsDsnUrl.String())).Require(t)
		defer fi.NoErrorF(builtInCertsDb.Close, t)
		err = builtInCertsDb.Ping()
		require.Falsef(t, strings.Contains(err.Error(), "bad dsn"), "actual dsn: %s", err)
		require.ErrorContains(t, err, "using system root CAs")
		expectedErrorType := &tls.CertificateVerificationError{}
		require.ErrorAs(t, err, &expectedErrorType)
	})

	t.Run("bad password", func(t *testing.T) {
		badPassDsn, err := url.Parse(dsn)
		require.NoError(t, err)
		for _, usr := range []*url.Userinfo{
			url.User("nopass"),
			url.UserPassword("wrong", "password"),
		} {
			t.Run(usr.Username(), func(t *testing.T) {
				badPassDsn.User = usr
				builtInCertsDb := fi.NoError(sql.Open("impala", badPassDsn.String())).Require(t)
				defer fi.NoErrorF(builtInCertsDb.Close, t)
				err = builtInCertsDb.Ping()
				var expectedErrorType *impala.AuthError
				require.ErrorAs(t, err, &expectedErrorType)
				require.ErrorContains(t, err, usr.Username())
			})
		}
	})
}

func startImpala3(t *testing.T) string {
	ctx := context.Background()
	c := fi.NoError(Setup(ctx)).Require(t)
	dsn := getDsn(ctx, t, c, url.User("impala"))
	t.Cleanup(func() {
		err := c.Terminate(ctx)
		assert.NoError(t, err)
	})
	return dsn
}

func startImpala4(t *testing.T) string {
	ctx := context.Background()
	c := setupStack(ctx, t)
	dsn := getDsn(ctx, t, c, impala4User)
	certPath := filepath.Join("..", "..", "compose", "testssl", "localhost.crt")
	dsn += "&auth=ldap"
	dsn += "&tls=true&ca-cert=" + fi.NoError(filepath.Abs(certPath)).Require(t)
	return dsn
}

func testPinger(t *testing.T, db *sql.DB) {
	require.NoError(t, db.Ping())
}

type selectTestCase struct {
	sql string
	res interface{}

	// The following are defined only for some tests
	dbType           string
	precision, scale *int64
	length           *int64
}

func testSelectOneIntoAny(t *testing.T, db *sql.DB) {
	sampletime, _ := time.Parse(time.RFC3339, "2019-01-01T12:00:00Z")

	tests := []selectTestCase{
		{sql: "1", res: int8(1)},
		{sql: "cast(1 as smallint)", res: int16(1)},
		{sql: "cast(1 as int)", res: int32(1)},
		{sql: "cast(1 as bigint)", res: int64(1)},
		{sql: "cast(1.0 as float)", res: float64(1)},
		{sql: "cast(1.0 as double)", res: float64(1)},
		{sql: "cast(1.0 as real)", res: float64(1)},
		{sql: "'str'", res: "str"},
		{sql: "cast(null as char(10))", res: nil, dbType: "CHAR", length: lo.ToPtr(int64(10))},
		{sql: "cast(1.3 as decimal(10, 2))", res: "1.30", dbType: "DECIMAL", precision: lo.ToPtr(int64(10)), scale: lo.ToPtr(int64(2))},
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
			query := fmt.Sprintf("select %s", tt.sql)
			dbRes, queryErr := conn.QueryContext(ctx, query)
			require.NoError(t, queryErr)
			defer fi.NoErrorF(dbRes.Close, t)
			require.True(t, dbRes.Next())
			err = dbRes.Scan(&res)
			require.NoError(t, err)
			require.Equal(t, tt.res, res)

			checkColumnType(t, dbRes, tt)
		})
	}
}

func checkColumnType(t *testing.T, dbRes *sql.Rows, tt selectTestCase) {
	colType := fi.NoError(dbRes.ColumnTypes()).Require(t)[0]
	expected := tt.res
	if expected != nil {
		// We compare the names first so we get a simpler message in case of a simple mismatch.
		actualScanType := colType.ScanType()
		require.Equal(t, reflect.TypeOf(expected).String(), actualScanType.String())
		require.Equal(t, reflect.TypeOf(expected), actualScanType)
	}

	nullable, hasNullable := colType.Nullable()
	require.True(t, hasNullable)
	require.True(t, nullable)

	if tt.dbType != "" {
		require.Equal(t, tt.dbType, colType.DatabaseTypeName())
	}

	if tt.precision != nil && tt.scale != nil {
		actualPrecision, actualScale, ok := colType.DecimalSize()
		require.True(t, ok)
		require.Equal(t, *tt.precision, actualPrecision)
		require.Equal(t, *tt.scale, actualScale)
	}

	if tt.length != nil {
		actualLength, ok := colType.Length()
		require.True(t, ok)
		require.Equal(t, *tt.length, actualLength)
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
	t.Run("Columns", func(t *testing.T) {
		res, err := m.GetColumns(context.Background(), "defaul%", "tes%", "%")
		require.NoError(t, err)
		require.True(t, slices.ContainsFunc(res, func(tbl impala.ColumnName) bool {
			return tbl.TableName == "test" && tbl.Schema == "default" && tbl.ColumnName == "a"
		}))
	})
}

func testInsert(t *testing.T, conn *sql.DB) {
	now := time.Now()
	var err error
	_, err = conn.Exec("DROP TABLE IF EXISTS test")
	require.NoError(t, err)
	_, err = conn.Exec("CREATE TABLE test(a varchar)")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err = conn.Exec("DROP TABLE IF EXISTS test")
		require.NoError(t, err)
	})

	t.Run("data inserted", func(t *testing.T) {
		insertRes, err := conn.Exec("INSERT INTO test (a) VALUES (?)", now)
		require.NoError(t, err)
		rowsAdded, err := insertRes.RowsAffected()
		require.NoError(t, err)
		require.Equal(t, int64(1), rowsAdded)

		// Use Prepare to exercise that codepath
		st, err := conn.Prepare("SELECT * FROM test WHERE a = ? LIMIT 1")
		require.NoError(t, err)
		selectRes, err := st.Query(now)
		require.NoError(t, err)
		defer fi.NoErrorF(selectRes.Close, t)
		require.True(t, selectRes.Next())
		var val string
		require.NoError(t, selectRes.Scan(&val))
		require.Equal(t, now.Format(hive.TimestampFormat), val)
		require.NoError(t, st.Close()) // close is no-op anyway
	})

	t.Run("cancel DML from Query", func(t *testing.T) {
		startTime := time.Now()
		dmlRes, err := conn.Query("INSERT INTO test (a) VALUES (cast(SLEEP(10000) as string))")
		require.NoError(t, err)
		err = dmlRes.Close()
		require.NoError(t, err)
		require.Less(t, time.Since(startTime), 5*time.Second)
	})

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

func toCloser(ct testcontainers.Container, t *testing.T) func() error {
	return func() error {
		t.Log("Terminating container", ct.GetContainerID())
		return ct.Terminate(context.Background())
	}
}

func setupStack(ctx context.Context, t *testing.T) testcontainers.Container {
	//nolint - deprecated but alternative doesn't allow customizing name; default name is invalid
	netReq := testcontainers.NetworkRequest{
		Driver: "bridge",
		Name:   "quickstart-network",
	}

	//nolint - deprecated see above
	containerNet, err := testcontainers.GenericNetwork(ctx, testcontainers.GenericNetworkRequest{
		NetworkRequest: netReq,
	})
	require.NoError(t, err)
	fi.CleanupF(t, lang.Bind(containerNet.Remove, context.Background()))

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
	fi.CleanupF(t, toCloser(ct, t))

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
	fi.CleanupF(t, toCloser(ct, t))

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
	fi.CleanupF(t, toCloser(ct, t))

	req = testcontainers.ContainerRequest{
		Image:      "ghcr.io/rroemhild/docker-test-openldap:master",
		Networks:   []string{netReq.Name},
		Name:       "ldapserver",
		WaitingFor: wait.ForLog("slapd starting"),
		HostConfigModifier: func(config *container.HostConfig) {
			config.Resources.Ulimits = append(config.Resources.Ulimits, &units.Ulimit{
				Name: "nofile",
				Hard: 1024,
				Soft: 1024,
			})
		},
	}
	ct, err = testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)
	fi.CleanupF(t, toCloser(ct, t))

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
			"-enable_ldap_auth",
			"-ldap_uri=ldap://ldapserver:10389",
			"-ldap_passwords_in_clear_ok",
			"-ldap_search_bind_authentication",
			"-ldap_allow_anonymous_binds=true",
			"-ldap_user_search_basedn=ou=people,dc=planetexpress,dc=com",
			"-ldap_user_filter=(&(objectClass=inetOrgPerson)(uid={0}))",
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
		//LogConsumerCfg: &testcontainers.LogConsumerConfig{
		//	Consumers: []testcontainers.LogConsumer{&testcontainers.StdoutLogConsumer{}},
		//},
	}
	ct, err = testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)
	fi.CleanupF(t, toCloser(ct, t))

	return ct
}

func getDsn(ctx context.Context, t *testing.T, c testcontainers.Container, userinfo *url.Userinfo) string {
	port := fi.NoError(c.MappedPort(ctx, dbPort)).Require(t).Port()
	host := fi.NoError(c.Host(ctx)).Require(t)

	u := &url.URL{
		Scheme:   "impala",
		Host:     net.JoinHostPort(host, port),
		User:     userinfo,
		RawQuery: "log=stderr",
	}
	return u.String()
}
