# Golang Apache Impala Driver 

<img src="./docs/logo.svg" width="64" alt="project logo - gopher with impala horns" align="right">

**The actively supported Apache Impala driver for Go's [database/sql](https://golang.org/pkg/database/sql) package**

This driver started as a fork of [github.com/bippio/go-impala](https://github.com/bippio/go-impala),
which hasn't been updated in over four years and appears to be abandoned.
Several issues have been fixed since then —
some [quite severe](https://github.com/sclgo/impala-go/pulls?q=is%3Apr+is%3Aclosed+label%3Abug).
The original codebase also didn't support Go modules.

[![Go Reference](https://pkg.go.dev/badge/github.com/sclgo/impala-go.svg)](https://pkg.go.dev/github.com/sclgo/impala-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/sclgo/impala-go)](https://goreportcard.com/report/github.com/sclgo/impala-go)
[![Tests](https://github.com/sclgo/impala-go/actions/workflows/ci.yml/badge.svg)](https://coveralls.io/github/sclgo/impala-go)
[![Coverage Status](https://coveralls.io/repos/github/sclgo/impala-go/badge.svg)](https://coveralls.io/github/sclgo/impala-go)

## Install

Add `impala-go` to your Go module:

```bash
go get github.com/sclgo/impala-go
```

Alternatively, see below how to use it as a CLI. `impala-go` does not use CGO.

## Connection Parameters and DSN

The data source name (DSN; connection string) uses a URL format:
`impala://username:password@host:port?param1=value&param2=value`

Driver name is `impala`.

### Parameters:

* `auth` - string. Authentication mode. Supported values: `noauth`, `ldap`.
* `tls` - boolean. Enable TLS
* `ca-cert` - The file that contains the public key certificate of the CA that signed the Impala certificate
* `batch-size` - integer value (default: 1024). Maximum number of rows fetched per request.
* `buffer-size`- in bytes (default: 4096). Buffer size for the Thrift transport.
* `mem-limit` - string value (example: 3m). Memory limit for query, as a share of available RAM or a fixed value. See
  <https://impala.apache.org/docs/build/html/topics/impala_mem_limit.html> for details.
* `query-timeout` - integer value in seconds. Query timeout - see 
  <https://impala.apache.org/docs/build/html/topics/impala_query_timeout_s.html> for details.
* `socket-timeout` - integer or string value (default: 5s). The maximum socket idle time, expressed as a
  time duration in this [syntax](https://pkg.go.dev/time#ParseDuration). If the value is an integer without
  a time unit, milliseconds are assumed.
* `connect-timeout` - integer or string value (default: 10s). The max wait for initial connection to server, 
  expressed as a time duration in this [syntax](https://pkg.go.dev/time#ParseDuration). If the value is an 
  integer without a time unit, milliseconds are assumed.
* `tls-insecure-skip-verify` - boolean. Disables TLS certificate verification by enabling the 
  [tls.Config.InsecureSkipVerify](https://pkg.go.dev/crypto/tls#Config.InsecureSkipVerify) option.
  Behaves the same way as `AllowSelfSignedCerts` in the official JDBC driver.
* `reuse-session` - boolean. Disables resetting the session when `database/sql` requests it.
  When this setting is enabled, this driver behaves consistently with the other DB drivers
  in the ecosystem but diverges somewhat from documented database/sql behavior.
  This setting is disabled by default for backward compatibility and alignment with 
  [published Go documentation](https://pkg.go.dev/database/sql/driver#SessionResetter).
  It must be enabled when this driver is used in `github.com/xo/usql`.
  `usql` returns the connection to the pool after each statement, relying on the typical driver behavior.
  

A string of this format can be constructed using the URL type in the net/url package.

```go
  query := url.Values{}
  query.Add("auth", "ldap")

  u := &url.URL{
      Scheme:   "impala",
      User:     url.UserPassword(username, password),
      Host:     net.JoinHostPort(hostname, port),
      RawQuery: query.Encode(),
  }
  db, err := sql.Open("impala", u.String())
```

Also, you can bypass the string-based data source name by using sql.OpenDB:

```go
  opts := impala.DefaultOptions
  opts.Host = hostname
  opts.UseLDAP = true
  opts.Username = username
  opts.Password = password

  connector := impala.NewConnector(&opts)
  db, err := sql.OpenDB(connector)
```

Impala supports numerous other session options which can be configured with the 
[SET statement](https://impala.apache.org/docs/build/html/topics/impala_set.html).
`mem-limit` and `query-timeout` are the only two such options the driver supports as part of the DSN.
Those DSN fields for those are an exception for backwards compatibility. The preferred way to set any
session option is issuing SET statements to a SQL connection. Users may find it useful to wrap the 
`driver.Connector` returned by `impala.NewConnector` so that a set of session options are automatically applied to
all created connections.

## CLI

`impala-go` is included in [xo/usql](https://github.com/xo/usql) - the universal SQL CLI, 
inspired by [psql](https://www.postgresql.org/docs/current/app-psql.html). 

[Install](https://github.com/xo/usql?tab=readme-ov-file#installing) `usql`, start it, then on its prompt, run:

```shell
\connect impala DSN
```

where DSN is a data source name in the format above. Review the `usql` [documentation](https://github.com/xo/usql#readme)
for other options.

The latest version of `usql` typically comes with the latest version of `impala-go` but if you need to use a different one,
you can prepare a custom build using [usqlgen](https://github.com/sclgo/usqlgen). For example, the following command
builds a `usql` binary in the working directory using `impala-go` from `master` branch:

```bash
go run github.com/sclgo/usqlgen@latest build --get github.com/sclgo/impala-go@master -- -tags impala
```

`usql` with `impala-go` is arguably a better CLI for Impala than the official impala-shell.
For one, `usql` is much easier to install.

## Example Go code

```go
package main

// Simple program to list databases and the tables

import (
	"context"
	"database/sql"
	"log"

	"github.com/sclgo/impala-go"
)

func main() {
	opts := impala.DefaultOptions

	opts.Host = "localhost" // impala host
	opts.Port = "21050"

	// enable LDAP authentication:
	//opts.UseLDAP = true
	//opts.Username = "<ldap username>"
	//opts.Password = "<ldap password>"
	//
	// enable TLS
	//opts.UseTLS = true
	//opts.CACertPath = "/path/to/cacert"

	connector := impala.NewConnector(&opts)
	db := sql.OpenDB(connector)
	defer func() {
		_ = db.Close()
	}()

	ctx := context.Background()

	rows, err := db.QueryContext(ctx, "SHOW DATABASES")
	if err != nil {
		log.Fatal(err)
	}

	var name, comment string
	databases := make([]string, 0) // databases will contain all the DBs to enumerate later
	for rows.Next() {
		if err := rows.Scan(&name, &comment); err != nil {
			log.Fatal(err)
		}
		databases = append(databases, name)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}
	log.Println("List of Databases", databases)

	tables, err := impala.NewMetadata(db).GetTables(ctx, "%", "%")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("List of Tables", tables)
}
```

Check out also [an open data end-to-end demo](compose/README.md).

## Data types

[Impala data types](https://impala.apache.org/docs/build/html/topics/impala_datatypes.html)
are mapped to Go types as expected, with the following exceptions:

* "Complex" types - MAP, STRUCT, ARRAY - are not supported. Impala itself has limited support for those.
  As a workaround, select individual fields or flatten such values within select statements.
* Decimals are converted to strings
  by [the Impala server API](https://github.com/apache/impala/blob/c5a0ec8/common/thrift/hive-1-api/TCLIService.thrift#L327).
  Either parse the decimal value after `Rows.Scan`,
  or use a custom [sql.Scanner](https://pkg.go.dev/database/sql#Scanner) implementation
  in `Row(s).Scan` e.g. `Decimal` from [github.com/cockroachdb/apd](https://github.com/cockroachdb/apd).
  Note that the processing of `sql.Scanner` within `Row(s).Scan` is a feature of the `database/sql` package,
  and not the driver. The [ScanType](https://pkg.go.dev/database/sql#ColumnType.ScanType)
  of such values is `string`, while the [DatabaseTypeName](https://pkg.go.dev/database/sql#ColumnType.DatabaseTypeName)
  is `DECIMAL`. Retrieving precision and scale using the
  [DecimalSize API](https://pkg.go.dev/database/sql#ColumnType.DecimalSize) is supported.

## Context support

The driver methods recognize [Context](https://pkg.go.dev/context) and support early cancellation in most cases.
Additionally, the `Query` methods return early before all rows are retrieved.
`Exec` methods return after the operation completes (this may be configurable in the future).
`Exec` methods can still be stopped early by cancelling the context from another goroutine.

It is also supported to use a `QueryContext` method on a [sql.Conn](https://pkg.go.dev/database/sql#Conn)
for a DDL/DML statement if you need the method to return before the statement completes.
In that case, calling [Rows.Next](https://pkg.go.dev/database/sql#Rows.Next)
will wait for the statement to complete and then return `false`.

## Compatibility and Support

The library is actively tested with Impala 4.4 and 3.4. All 3.x and 4.x minor
versions should work well. 2.x is also supported on a best-effort basis.

While Impala shares the majority of its API with Apache Hive, this driver doesn't support Hive.
Instead, it is recommended to use a dedicated Hive driver or client.
Please file an issue if you find it more valuable to use this driver with Hive compared to
the existing drivers.

The library is *not* compatible with [TinyGo](https://tinygo.org/) because Thrift for Go
doesn't support it. The Thrift code incompatible with TinyGo is not referenced by
impala-go but compilation fails nonetheless. Last checked with `tinygo 0.41.1`, `thrift
0.23`, and `Go 1.26` on `2026-05-10`. (Dev note: Any new release of Thrift or TinyGo may
resolve the issue. Run `make test-tinygo` after updates to check again.) 
Thrift team tracks progress on TinyGo support at <https://issues.apache.org/jira/browse/THRIFT-5209>.

File any issues that you encounter as GitHub issues.

## Versioning

The library follows semantic versioning, as specified in [SemVer 2.0.0](https://semver.org/), 
and will use semantic import versioning ([SIV](https://research.swtch.com/vgo-import)), if a
2.0 version is ever needed. However, the [rare exceptions](https://go.dev/doc/go1compat#expectations) 
to the semantic versioning rules that are allowed for the Go language and standard library, 
apply to this library as well. For example, a minor release can include a breaking change 
if the change was required to fix a security issue. Review the rest of the exceptions at
<https://go.dev/doc/go1compat#expectations>.

[gorelease tool](https://pkg.go.dev/golang.org/x/exp/cmd/gorelease) is included in CI to
automate the detection of most semantic versioning violations.

The minimum Go version may increase in minor, not patch, releases following general practice.
The last two Go minor releases will always be supported. 

## Copyright and acknowledgements

This library started as a fork of [github.com/bippio/go-impala](https://github.com/bippio/go-impala),
under [the MIT license](https://github.com/bippio/go-impala/blob/ebab2bf/LICENSE). This library retains the same
license.

The [project logo](/docs/logo.svg) combines the Golang Gopher from
[github.com/golang-samples/gopher-vector](https://github.com/golang-samples/gopher-vector)
with the [Apache Impala logo](https://impala.apache.org/img/impala-logo.png), licensed under the Apache 2 license.
