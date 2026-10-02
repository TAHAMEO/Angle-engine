#!/usr/bin/env bash
# Local Redis for development and tests (rate limiting).
#   scripts/dev-redis.sh start|stop|status
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${ANGEL_REDIS_PORT:-63799}"
DIR="$ROOT/var/redis"
case "${1:-}" in
  start)
    mkdir -p "$DIR"
    if redis-cli -p "$PORT" ping >/dev/null 2>&1; then echo "Redis already running on $PORT"; exit 0; fi
    redis-server --port "$PORT" --bind 127.0.0.1 --dir "$DIR" --daemonize yes \
      --save "" --appendonly no --logfile "$DIR/redis.log" --pidfile "$DIR/redis.pid"
    for _ in $(seq 1 50); do redis-cli -p "$PORT" ping >/dev/null 2>&1 && break; sleep 0.1; done
    echo "Redis started on 127.0.0.1:$PORT" ;;
  stop) redis-cli -p "$PORT" shutdown nosave >/dev/null 2>&1 || true; echo "Redis stopped" ;;
  status) redis-cli -p "$PORT" ping ;;
  *) echo "usage: $0 {start|stop|status}" >&2; exit 2 ;;
esac
