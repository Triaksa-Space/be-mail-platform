#!/bin/sh
set -e

if [ "$1" = "server" ]; then
  echo "Running migrations..."
  goose -dir /app/migrations mysql "mailria_user:mailriauserpassword@tcp(mysql:3306)/mailria?parseTime=true" up
fi

exec ./mailria "$@"
