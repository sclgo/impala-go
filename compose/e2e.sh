#!/usr/bin/env sh
set -ex

docker compose down -v
docker compose up --wait
go run ../examples/enumerateDB.go

# if impala-go from current source is needed, build usql beforehand
[ -f usql ] || go run github.com/sclgo/usqlgen@latest build -- -tags impala

docker compose exec healthcheck cp /combinedjar/esri-gis.jar /user/hive/warehouse
./usql impala://localhost -f opendata/gis.sql
./usql impala://localhost -f opendata/create_table_latest.sql
./usql impala://localhost -f opendata/query.sql
