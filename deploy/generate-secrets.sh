#!/usr/bin/env bash
# Create the secret files used by docker-compose.yml (deploy/secrets/). Existing files are kept unless FORCE=1.
# Changing database passwords after the first start also requires ALTER ROLE … PASSWORD in PostgreSQL.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/secrets"
mkdir -p "$DIR"
chmod 700 "$DIR"   # the directory protects the files on the host; containers read them via bind mounts

gen() { python3 -c 'import secrets; print(secrets.token_urlsafe(32))'; }

write() {
  local name="$1" value="$2"
  if [[ -e "$DIR/$name" && "${FORCE:-0}" != "1" ]]; then
    echo "kept     $name"
    return
  fi
  printf '%s' "$value" >"$DIR/$name"
  chmod 644 "$DIR/$name"
  echo "created  $name"
}

for role in owner app worker maintenance; do
  write "db_${role}_password" "$(gen)"
done
write postgres_password "$(gen)"
write redis_password "$(gen)"

url() { printf 'postgresql+asyncpg://ae_%s:%s@postgres:5432/angel_engine' "$1" "$(cat "$DIR/db_$1_password")"; }
write angel_database_url "$(url app)"
write angel_database_url_worker "$(url worker)"
write angel_database_url_maintenance "$(url maintenance)"
write angel_database_url_owner "$(url owner)"
write angel_redis_url "redis://:$(cat "$DIR/redis_password")@redis:6379/0"

echo "secrets in $DIR (keep them out of version control and backups of the repository)"
