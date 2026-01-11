package ftest

import (
	"context"
	"database/sql"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/jcmturner/krb5test"
	"github.com/murfffi/gorich/fi"
	"github.com/murfffi/gorich/helperr"
	"github.com/murfffi/krb5writer"
	"github.com/stretchr/testify/require"
)

func TestKerberos(t *testing.T) {
	kdc := createKdc(t)
	defer kdc.Close()

	tmpDir := t.TempDir()

	dsn := startImpala4Kerberos(t, kdc, tmpDir)
	db := fi.NoError(sql.Open("impala", dsn)).Require(t)
	defer fi.NoErrorF(db.Close, t)
	t.Run("kerberos happy case", func(t *testing.T) {
		runHappyCases(t, db)
	})
}

func createKdc(t *testing.T) *krb5test.KDC {
	l := log.New(os.Stderr, "KDC Test Server: ", log.LstdFlags)
	p := make(map[string][]string)
	p["impala/impala_host.example.com@TEST.EXAMPLE.COM"] = []string{""}
	p["HTTP/impala_host.example.com@TEST.EXAMPLE.COM"] = []string{}
	kdc, err := krb5test.NewKDC(p, l)
	require.NoError(t, err)
	return kdc
}

func startImpala4Kerberos(t *testing.T, kdc *krb5test.KDC, tmpDir string) string {
	ctx := context.Background()
	c := setupStack(ctx, t, StackOpts{
		keytabPath:   writeKeytab(t, kdc, tmpDir),
		krb5ConfPath: writeKrb5Conf(t, kdc, tmpDir),
	})
	dsn := getDsn(ctx, t, c, impala4User)
	certPath := filepath.Join(getSslConfDir(t), "localhost.crt")
	dsn += "&auth=ldap"
	dsn += "&tls=true&ca-cert=" + fi.NoError(filepath.Abs(certPath)).Require(t)
	return dsn
}

func writeKrb5Conf(t *testing.T, kdc *krb5test.KDC, tmpDir string) string {
	path := filepath.Join(tmpDir, "impala.krb5conf")
	err := krb5writer.WriteKrb5Conf(kdc.KRB5Conf, path)
	require.NoError(t, err)
	return path
}

func writeKeytab(t *testing.T, kdc *krb5test.KDC, tmpDir string) string {
	keytabPath := filepath.Join(tmpDir, "impala.keytab")
	ktFile, err := os.OpenFile(keytabPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	require.NoError(t, err)
	defer helperr.CloseQuietly(ktFile)
	_, err = kdc.Keytab.Write(ktFile)
	require.NoError(t, err)
	require.NoError(t, ktFile.Close())
	return keytabPath
}
