#!/bin/sh
set -e

if [ "$1" = "server" ]; then
  echo "Running migrations..."
  goose -dir /app/migrations mysql "mailria_prod:aa!ma1Lr!a@tcp(db-mailria-prod.c9yag8g0s8mo.ap-southeast-1.rds.amazonaws.com:3306)/mailsaja_dev?parseTime=true" up
fi

exec ./mailria "$@"
