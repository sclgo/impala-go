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
