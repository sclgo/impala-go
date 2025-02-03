#!/usr/bin/env sh
set -e
docker compose down --remove-orphans
docker compose up --wait
