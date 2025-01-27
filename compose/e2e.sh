#!/usr/bin/env sh
set -ex

docker compose down -v
docker compose up --wait
go run ../examples/enumerateDB.go
[ -f usql ] || go run github.com/sclgo/usqlgen@latest build --import github.com/sclgo/impala-go -- -tags no_base
./usql impala:impala://localhost -f opendata/create_table.sql
./usql impala:impala://localhost -f opendata/query.sql
