#!/usr/bin/env sh
# Creates docker/.env.mongo with random root credentials (once) and prints the
# connection string for AGENTOS_MONGO_URI. Never commit docker/.env.mongo.
set -eu
ENV_FILE="$(dirname "$0")/.env.mongo"

if [ ! -f "$ENV_FILE" ]; then
  PASSWORD="$(head -c 24 /dev/urandom | base64 | tr -d '+/=')"
  printf 'MONGO_INITDB_ROOT_USERNAME=agentos\nMONGO_INITDB_ROOT_PASSWORD=%s\n' "$PASSWORD" > "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  echo "Created $ENV_FILE" >&2
fi

. "$ENV_FILE"
echo "mongodb://${MONGO_INITDB_ROOT_USERNAME}:${MONGO_INITDB_ROOT_PASSWORD}@127.0.0.1:27017/?replicaSet=rs0&authSource=admin"
