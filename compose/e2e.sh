#!/usr/bin/env sh
set -ex

docker compose down -v
docker compose up --wait
go run ../examples/enumerateDB.go
[ -f usql ] || go run github.com/sclgo/usqlgen@latest build --import github.com/sclgo/impala-go -- -tags no_base
docker compose exec healthcheck cp /combinedjar/esri-gis.jar /user/hive/warehouse
./usql impala:impala://localhost -f opendata/gis.sql
./usql impala:impala://localhost -f opendata/create_table_latest.sql
./usql impala:impala://localhost -f opendata/query.sql
