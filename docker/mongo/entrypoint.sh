#!/usr/bin/env bash
# Generates the replica-set keyfile inside the container (mongod refuses keyfiles
# with group/other permissions, which Windows bind mounts cannot express), then
# hands over to the official image entrypoint.
set -euo pipefail

KEYFILE=/data/configdb/rs0.keyfile
if [ ! -s "$KEYFILE" ]; then
  openssl rand -base64 756 > "$KEYFILE"
fi
chmod 400 "$KEYFILE"
chown mongodb:mongodb "$KEYFILE"

exec docker-entrypoint.sh mongod --replSet rs0 --keyFile "$KEYFILE" --bind_ip_all
