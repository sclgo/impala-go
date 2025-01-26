#!/usr/bin/env sh
set -ex

docker compose down -v
docker compose up --wait
go run ../examples/enumerateDB.go