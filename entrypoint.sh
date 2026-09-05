#!/bin/sh
set -eu
mkdir -p "${DATA_DIR:-/data}/keys" "${DATA_DIR:-/data}/logs"
if [ ! -f "${DATA_DIR:-/data}/tunnels.json" ]; then
  cp /app/defaults/tunnels.json "${DATA_DIR:-/data}/tunnels.json"
fi
chmod 600 "${DATA_DIR:-/data}"/keys/* 2>/dev/null || true
if [ "${GUI_PASS:-changeme}" = "changeme" ]; then
  echo "WARNING: GUI_PASS is still 'changeme' - change it in compose/env" >&2
fi
exec python3 /app/app.py
