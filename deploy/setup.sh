#!/bin/sh
# Render the deploy configs with a generated RPC password into the shared
# `config` volume. Run automatically by the compose `setup` service before
# bitcoind and the pool start -- you don't invoke this by hand.
#
# Idempotent: the password is generated once (stored in the volume) and reused
# on every later start, so bitcoind and the pool always share matching
# credentials. `docker compose down -v` wipes the volume and, on the next `up`,
# a fresh password is generated.
set -eu

PW_FILE=/config/.rpcpassword

if [ -s "$PW_FILE" ]; then
    PW=$(cat "$PW_FILE")
    echo "setup: reusing the existing RPC password"
else
    PW=$(head -c 64 /dev/urandom | sha256sum | cut -c1-48)
    printf '%s' "$PW" > "$PW_FILE"
    chmod 600 "$PW_FILE"
    echo "setup: generated a new RPC password"
fi

# Substitute the placeholder in every mounted template (hex password => safe
# with a '/' sed delimiter) and write the result into the shared volume.
for tpl in /templates/*; do
    sed "s/CHANGE_ME_before_deploying/$PW/g" "$tpl" > "/config/$(basename "$tpl")"
done

echo "setup: rendered $(ls /templates | tr '\n' ' ')-> shared config volume"
