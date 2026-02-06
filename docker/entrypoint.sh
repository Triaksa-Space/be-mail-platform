#!/bin/sh
set -e

if [ "$1" = "server" ]; then
  echo "Running migrations..."
  goose -dir /app/migrations mysql "$DATABASE_URL" up
fi

exec ./mailria "$@"
