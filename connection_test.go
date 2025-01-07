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
}

func runSuite(t *testing.T, dsn string) {
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
	compose, err := tc.NewDockerCompose("compose/quickstart.yml")
	require.NoError(t, err)
	compose = compose.WithEnv(map[string]string{
		"IMPALA_QUICKSTART_IMAGE_PREFIX": "apache/impala:4.4.1-",
		"QUICKSTART_LISTEN_ADDR":         "0.0.0.0",
	})
	t.Cleanup(func() {
		assert.NoError(t, compose.Down(context.Background(), tc.RemoveOrphans(true), tc.RemoveImagesLocal))
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	require.NoError(t, compose.WaitForService("impalad-1", waitRule).Up(ctx, tc.Wait(true)))
	c, err := compose.ServiceContainer(ctx, "impalad-1")
	require.NoError(t, err)
	return GetDsn(ctx, t, c)
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
		// confirms that fetch 0 rows with hasMoreRows = true is correctly handled
		// relies on FETCH_ROWS_TIMEOUT_MS="1000", configured below
		{sql: "sleep(5000)", res: true},
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
		Scheme: "impala",
		Host:   net.JoinHostPort(host, port),
		User:   url.User("impala"),
	}
	return u.String()
}
