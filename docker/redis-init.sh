#!/usr/bin/env sh
# Creates docker/.env.redis with random password (once) and prints the
# connection string for AGENTOS_REDIS_URI. Never commit docker/.env.redis.
set -eu
ENV_FILE="$(dirname "$0")/.env.redis"

if [ ! -f "$ENV_FILE" ]; then
  PASSWORD="$(head -c 24 /dev/urandom | base64 | tr -d '+/=')"
  printf 'AGENTOS_REDIS_PASSWORD=%s\n' "$PASSWORD" > "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  echo "Created $ENV_FILE" >&2
fi

. "$ENV_FILE"
echo "redis://:${AGENTOS_REDIS_PASSWORD}@127.0.0.1:${AGENTOS_REDIS_PORT:-6379}/0"
