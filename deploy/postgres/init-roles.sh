#!/usr/bin/env bash
# First-start initialisation of the PostgreSQL container: least-privilege roles and the database.
# Passwords come from Docker secrets; nothing is written to the image.
set -euo pipefail

read_secret() { tr -d '\n' < "/run/secrets/$1"; }

OWNER_PW="$(read_secret db_owner_password)"
APP_PW="$(read_secret db_app_password)"
WORKER_PW="$(read_secret db_worker_password)"
MAINT_PW="$(read_secret db_maintenance_password)"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  -v owner_pw="$OWNER_PW" -v app_pw="$APP_PW" -v worker_pw="$WORKER_PW" -v maint_pw="$MAINT_PW" <<'SQL'
CREATE ROLE ae_owner LOGIN PASSWORD :'owner_pw';
CREATE ROLE ae_app LOGIN PASSWORD :'app_pw' NOBYPASSRLS;
CREATE ROLE ae_worker LOGIN PASSWORD :'worker_pw' NOBYPASSRLS;
CREATE ROLE ae_maintenance LOGIN PASSWORD :'maint_pw' BYPASSRLS;
CREATE DATABASE angel_engine OWNER ae_owner;
REVOKE ALL ON DATABASE angel_engine FROM PUBLIC;
GRANT CONNECT ON DATABASE angel_engine TO ae_app, ae_worker, ae_maintenance;
SQL
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname angel_engine \
  -c "REVOKE CREATE ON SCHEMA public FROM PUBLIC; ALTER SCHEMA public OWNER TO ae_owner;"
