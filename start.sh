#!/bin/sh
set -eu

: "${PORT:?PORT must be set by Railway or your local environment}"
: "${SOCKS_USERNAME:?SOCKS_USERNAME must be set}"
: "${SOCKS_PASSWORD:?SOCKS_PASSWORD must be set}"

exec node src/server.js
