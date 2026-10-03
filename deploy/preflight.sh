#!/usr/bin/env bash
# Run by `make up` and `make demo` before anything is generated or started: can this user reach Docker, and does
# an existing Angel Engine database belong to this copy of the project?
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! problem=$(docker info 2>&1 >/dev/null); then
  if grep -qi "permission denied" <<<"$problem"; then
    cat >&2 <<'EOF'
Docker is installed, but this user may not use it yet ("permission denied" on the Docker socket).
Add yourself to the docker group once:
    sudo usermod -aG docker "$USER"
then log out and back in (or restart), or run `newgrp docker` to use it in this terminal now. Then run make again.
EOF
  else
    printf '%s\n\n' "$problem" >&2
    echo "Docker is not running or not installed. Start it with: sudo systemctl enable --now docker" >&2
  fi
  exit 1
fi

# PostgreSQL keeps the passwords a database was created with. Another copy of the project (a second clone or a
# fresh download) would generate new ones and could not connect to it.
if [[ ! -e "$DIR/secrets/db_owner_password" ]] && docker volume inspect angel-engine_pgdata >/dev/null 2>&1; then
  cat >&2 <<'EOF'
Docker already holds an Angel Engine database (volume angel-engine_pgdata) that was created by another copy of this
project, and this copy does not have its passwords (deploy/secrets/). Either:
  - keep that data: copy the deploy/secrets/ folder from the other copy into this one, or
  - delete it and start over (the offline demo's data can always be recreated):
        make demo-reset
Then run make again.
EOF
  exit 1
fi
