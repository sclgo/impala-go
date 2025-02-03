# Golang Apache Impala Driver 

<img src="./docs/logo.svg" width="64" alt="project logo - gopher with impala horns" align="right">

**The actively supported Apache Impala driver for Go's [database/sql](https://golang.org/pkg/database/sql) package**

This driver started as a fork of [github.com/bippio/go-impala](https://github.com/bippio/go-impala),
which hasn't been updated in over four years and appears to be abandoned.
Several issues have been fixed since - some [quite severe](https://github.com/sclgo/impala-go/pulls?q=is%3Apr+is%3Aclosed+label%3Abug).

[![Go Reference](https://pkg.go.dev/badge/github.com/sclgo/impala-go.svg)](https://pkg.go.dev/github.com/sclgo/impala-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/sclgo/impala-go)](https://goreportcard.com/report/github.com/sclgo/impala-go)
[![Tests](https://github.com/sclgo/impala-go/actions/workflows/ci.yml/badge.svg)](https://coveralls.io/github/sclgo/impala-go)
[![Coverage Status](https://coveralls.io/repos/github/sclgo/impala-go/badge.svg)](https://coveralls.io/github/sclgo/impala-go)

## Install

Add `impala-go` to your Go module:

```bash
go get github.com/sclgo/impala-go
```

Alternatively, see below how to use as a CLI.

## Connection Parameters and DSN

The connection string uses a URL format: impala://username:password@host:port?param1=value&param2=value

### Parameters:

* `auth` - string. Authentication mode. Supported values: "noauth", "ldap"
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

Also, you can bypass string-base data source name by using sql.OpenDB:

```go
  opts := impala.DefaultOptions
  opts.Host = hostname
  opts.UseLDAP = true
  opts.Username = username
  opts.Password = password

  connector := impala.NewConnector(&opts)
  db := sql.OpenDB(connector)
```


## Try out with as a CLI

`impala-go` is compatible with [xo/usql](https://github.com/xo/usql) - the universal SQL CLI, 
inspired by [psql](https://www.postgresql.org/docs/current/app-psql.html). 
Since `impala-go` is not yet included in `usql` by default, you need a Go 1.21+ runtime to build a bundle
from source with [usqlgen](https://github.com/sclgo/usqlgen).

To build the CLI, run:

```bash
go run github.com/sclgo/usqlgen@latest build --import github.com/sclgo/impala-go -- -tags no_base
```

To connect to Impala in interactive mode, run:

```bash
./usql impala:DSN
```

In that command, DSN is a connection string in the format shown above. Note that the DSN itself starts with `impala:`.

For example, to run `show databases` in an Impala instance on localhost, use:

```bash
./usql impala:impala://localhost -c "show databases"
```

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

## Support

The library is actively tested with Impala 4.1 and 3.4.
All 3.x and 4.x minor versions should work well. 2.x is also supported
on a best-effort basis.

File any issues that you encounter as Github issues.

## Copyright and acknowledgements

This library started as a fork of [github.com/bippio/go-impala](https://github.com/bippio/go-impala),
under [the MIT license](https://github.com/bippio/go-impala/blob/ebab2bf/LICENSE). This library retains the same
license.

The [project logo](/docs/logo.svg) combines the Golang Gopher from
[github.com/golang-samples/gopher-vector](https://github.com/golang-samples/gopher-vector)
with the [Apache Impala logo](https://impala.apache.org/img/impala-logo.png), licensed under the Apache 2 license.