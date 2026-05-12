package ftest

import (
	"context"
	"database/sql/driver"

	"github.com/sclgo/impala-go"
)

type dynConnector func() *impala.Options

func (d dynConnector) Connect(ctx context.Context) (driver.Conn, error) {
	opts := d()
	return impala.NewConnector(opts).Connect(ctx)
}

func (d dynConnector) Driver() driver.Driver {
	return &impala.Driver{}
}

var _ driver.Connector = dynConnector(nil)
