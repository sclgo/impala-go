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
* `batch-size` - integer value (default: 1024). Maximum number of rows fetched per request
* `buffer-size`- in bytes (default: 4096); Buffer size for the Thrift transport 
* `mem-limit` - string value (example: 3m); Memory limit for query 	

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
As expected, the `Query` methods return early before all rows are retrieved.
`Exec` methods return after the operation completes (this may be configurable in the future).
`Exec` methods can still be stopped early by cancelling the context from another goroutine.

It is also supported to use a `Query` method for a DDL/DML statement if you need the method
to return before the statement completes.
In that case, calling [Rows.Next](https://pkg.go.dev/database/sql#Rows.Next)
will wait for the statement to complete and then return `false`.

## Compatibility and Support

The library is actively tested with Impala 4.4 and 3.4.
All 3.x and 4.x minor versions should work well. 2.x is also supported
on a best-effort basis.

File any issues that you encounter as GitHub issues.

The library is *not* compatible with [TinyGo](https://tinygo.org/) because
Thrift for Go requires [tls.Listen](https://pkg.go.dev/crypto/tls#Listen) which is not implemented by TinyGo at this
time.

## Copyright and acknowledgements

This library started as a fork of [github.com/bippio/go-impala](https://github.com/bippio/go-impala),
under [the MIT license](https://github.com/bippio/go-impala/blob/ebab2bf/LICENSE). This library retains the same
license.

The [project logo](/docs/logo.svg) combines the Golang Gopher from
[github.com/golang-samples/gopher-vector](https://github.com/golang-samples/gopher-vector)
with the [Apache Impala logo](https://impala.apache.org/img/impala-logo.png), licensed under the Apache 2 license.
