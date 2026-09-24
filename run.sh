#!/usr/bin/env bash
# Secure File Guard — start script
# Respects platform PORT (Render/Railway/Heroku) and binds 0.0.0.0 behind proxies.
set -e
cd "$(dirname "$0")"
export SFG_HOST="${SFG_HOST:-0.0.0.0}"
export SFG_PORT="${PORT:-${SFG_PORT:-8000}}"
exec python3 -m uvicorn app.main:app --host "$SFG_HOST" --port "$SFG_PORT" \
  --proxy-headers --forwarded-allow-ips '*' "$@"
