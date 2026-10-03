#!/usr/bin/env bash
# Local PostgreSQL 16 cluster for development and tests.
#
#   scripts/dev-postgres.sh init           create the cluster, roles and databases
#   scripts/dev-postgres.sh start          start the server (port $ANGEL_PG_PORT, default 54329)
#   scripts/dev-postgres.sh stop           stop the server
#   scripts/dev-postgres.sh status         show server status
#   scripts/dev-postgres.sh reset          stop, delete and re-create everything
#   scripts/dev-postgres.sh createdb NAME  create another application database (if missing)
#
# Roles (development passwords only — production uses secrets):
#   ae_owner        owns the schema, runs migrations
#   ae_app          API process; row-level security is enforced
#   ae_worker       background worker; row-level security is enforced
#   ae_maintenance  retention/purge jobs; BYPASSRLS
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PG_BIN="${PG_BIN:-$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1)}"
DATA_DIR="${ANGEL_PG_DATA:-$ROOT/var/postgres/data}"
RUN_DIR="${ANGEL_PG_RUN:-$ROOT/var/postgres/run}"
LOG_FILE="$ROOT/var/postgres/postgres.log"
PORT="${ANGEL_PG_PORT:-54329}"

as_pg() {
  if [[ "$(id -u)" == "0" ]]; then
    runuser -u postgres -- "$@"
  else
    "$@"
  fi
}

psql_super() {
  as_pg "$PG_BIN/psql" -h "$RUN_DIR" -p "$PORT" -U postgres -v ON_ERROR_STOP=1 -q "$@"
}

cmd_init() {
  if [[ -f "$DATA_DIR/PG_VERSION" ]]; then
    echo "cluster already initialised at $DATA_DIR"
    return 0
  fi
  mkdir -p "$DATA_DIR" "$RUN_DIR"
  if [[ "$(id -u)" == "0" ]]; then
    chown -R postgres:postgres "$ROOT/var/postgres"
  fi
  chmod 700 "$DATA_DIR"
  as_pg "$PG_BIN/initdb" -D "$DATA_DIR" -U postgres --auth-local=trust --auth-host=scram-sha-256 \
    --encoding=UTF8 --locale=C.UTF-8 >/dev/null
  cat >>"$DATA_DIR/postgresql.conf" <<EOF
listen_addresses = '127.0.0.1'
port = $PORT
unix_socket_directories = '$RUN_DIR'
password_encryption = scram-sha-256
max_connections = 200
shared_buffers = 128MB
log_min_duration_statement = 2000
EOF
  cmd_start
  psql_super <<'SQL'
CREATE ROLE ae_owner LOGIN PASSWORD 'ae_owner_dev';
CREATE ROLE ae_app LOGIN PASSWORD 'ae_app_dev' NOBYPASSRLS;
CREATE ROLE ae_worker LOGIN PASSWORD 'ae_worker_dev' NOBYPASSRLS;
CREATE ROLE ae_maintenance LOGIN PASSWORD 'ae_maintenance_dev' BYPASSRLS;
SQL
  for db in angel_engine angel_engine_test angel_engine_e2e; do
    cmd_createdb "$db"
  done
  echo "PostgreSQL ready on 127.0.0.1:$PORT (databases angel_engine, angel_engine_test, angel_engine_e2e)"
}

cmd_createdb() {
  local db="${1:?database name required}"
  [[ "$db" =~ ^[a-z_][a-z0-9_]*$ ]] || { echo "invalid database name: $db" >&2; exit 2; }
  if [[ -n "$(psql_super -tA -c "SELECT 1 FROM pg_database WHERE datname = '$db'")" ]]; then
    return 0
  fi
  psql_super <<SQL
CREATE DATABASE $db OWNER ae_owner;
REVOKE ALL ON DATABASE $db FROM PUBLIC;
GRANT CONNECT ON DATABASE $db TO ae_app, ae_worker, ae_maintenance;
SQL
  psql_super -d "$db" -c "REVOKE CREATE ON SCHEMA public FROM PUBLIC; ALTER SCHEMA public OWNER TO ae_owner;"
  echo "created database $db"
}

cmd_start() {
  if as_pg "$PG_BIN/pg_ctl" -D "$DATA_DIR" status >/dev/null 2>&1; then
    echo "PostgreSQL already running"
    return 0
  fi
  as_pg "$PG_BIN/pg_ctl" -D "$DATA_DIR" -l "$LOG_FILE" -w -t 30 start >/dev/null
  echo "PostgreSQL started on 127.0.0.1:$PORT"
}

cmd_stop() {
  as_pg "$PG_BIN/pg_ctl" -D "$DATA_DIR" -m fast stop >/dev/null 2>&1 || true
  echo "PostgreSQL stopped"
}

cmd_status() {
  as_pg "$PG_BIN/pg_ctl" -D "$DATA_DIR" status || true
}

cmd_reset() {
  cmd_stop
  rm -rf "$ROOT/var/postgres"
  cmd_init
}

case "${1:-}" in
  init) cmd_init ;;
  start) cmd_start ;;
  stop) cmd_stop ;;
  status) cmd_status ;;
  reset) cmd_reset ;;
  createdb) cmd_createdb "${2:-}" ;;
  *) echo "usage: $0 {init|start|stop|status|reset|createdb NAME}" >&2; exit 2 ;;
esac
