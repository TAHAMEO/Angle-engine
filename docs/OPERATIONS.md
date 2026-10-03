# Operations

This guide is for the people who deploy and run Angel Engine: installation, configuration, backups, key handling,
retention, upgrades, monitoring and abuse handling. Read [SECURITY.md](SECURITY.md) and
[PRIVACY.md](PRIVACY.md) first.

## Deployment

The supported deployment is Docker Compose on one host (`deploy/docker-compose.yml`):

| Service | Role | Networks |
|---|---|---|
| `caddy` | TLS termination (automatic certificates), HSTS, routing, redacted access log | `edge` (published 80/443), `frontend` |
| `web` | Next.js web client | `frontend` (internal) |
| `api` | FastAPI | `frontend`, `backend` (both internal) |
| `worker-analysis` | Queues `analysis`, `maintenance`: scanning, sandboxed image and page parsing, reports, purges, key rotation | `backend` only — **no internet access** |
| `worker-egress` | Queues `egress`, `ai`: connectors, TinEye, Google Cloud Vision, Claude | `backend`, `egress` |
| `postgres` | PostgreSQL 16 with the four application roles | `backend` |
| `redis` | Rate-limit counters only (no persistence, password-protected) | `backend` |
| `clamav` | Malware scanning (`clamd`) and signature updates | `backend`, `egress` |
| `keys-init`, `migrate` | One-shot: create the keyring, apply database migrations | none / `backend` |

Containers run as non-root with read-only root file systems, all capabilities dropped and `no-new-privileges`.
Named volumes: `pgdata` (database), `storage` (encrypted files), `keys` (**the keyring**), `clamdb`, `caddy_data`,
`caddy_config`.

### First installation

Requirements: a Linux host with Docker Engine and the Compose plugin, a DNS name pointing at the host, ports 80
and 443 reachable (for certificates), 4 vCPU / 8 GB RAM / 50 GB disk as a starting point (ClamAV alone needs about
1.5 GB of RAM).

```bash
cp deploy/.env.example deploy/.env       # set ANGEL_DOMAIN, ANGEL_OPERATOR_CONTACT, optional API keys
make up                                  # generates deploy/secrets/, builds images, migrates, starts everything
docker compose -f deploy/docker-compose.yml run --rm api \
  angel-engine create-admin --email admin@your-org.example --name "Platform Admin"
```

`create-admin` asks for a password (or prints a generated one when there is no terminal). Sign in at
`https://<ANGEL_DOMAIN>`, enrol the authenticator app (mandatory), store the recovery codes, then:

1. Review **Administration → Retention** (defaults below).
2. Check **Administration → Connectors**: which sources are ready and which need keys.
3. Approve access requests under **Administration → Users** and assign roles. Appoint at least one supervisor who
   is not an investigator, so individual-subject investigations can be approved by someone else.
4. Have counsel review the legal templates in `backend/src/angel_engine/legal/` before real use. Changing a
   document's version forces every user to accept it again.
5. Set up backups (below) **before** collecting real data.

ClamAV downloads its signatures on first start (several minutes). Uploads wait in `scanning` until `clamd` is
ready; scanning never fails open.

### Configuration

Settings are environment variables prefixed `ANGEL_` (`backend/src/angel_engine/config.py`); secrets are read
from Docker secrets in `/run/secrets` (`ANGEL_SECRETS_DIR`). The important ones:

| Variable | Default | Notes |
|---|---|---|
| `ANGEL_DOMAIN` (Compose) | — | Public host name; sets `ANGEL_PUBLIC_ORIGIN=https://<domain>` |
| `ANGEL_OPERATOR_CONTACT` | — | Organizational contact sent to sources that require one (SEC EDGAR) |
| `ANGEL_BIND_ADDRESS` (Compose) | all interfaces | Set `127.0.0.1` on a laptop or workstation so only that machine can reach the platform |
| `ANGEL_BOT_INFO_URL` | `https://<domain>/legal/responsible-use` | Linked from the connector User-Agent; set a public page when the domain is `localhost` |
| `ANGEL_ANTHROPIC_API_KEY` | — | Enables the Claude assistant; without it the assistant is shown as unavailable |
| `ANGEL_AI_MODEL` | `claude-opus-5-5` | |
| `ANGEL_AI_DAILY_TOKEN_BUDGET_PER_USER` | 2,000,000 | |
| `ANGEL_POLICY_LLM_CLASSIFIER` | `false` | Adds the Claude classifier to the rule-based policy engine (it can raise decisions, and lower a soft match by at most one level, never below *warn*) |
| `ANGEL_BRAVE_API_KEY`, `ANGEL_TINEYE_API_KEY`, `ANGEL_GOOGLE_VISION_API_KEY`, `ANGEL_GITHUB_TOKEN`, `ANGEL_STACKEXCHANGE_KEY` | — | Keyed connectors |
| `ANGEL_DISABLED_CONNECTORS` | `[]` | JSON list of connector ids to switch off |
| `ANGEL_SESSION_IDLE_MINUTES` / `ANGEL_SESSION_ABSOLUTE_HOURS` | 30 / 12 | |
| `ANGEL_REGISTRATION_OPEN` | `true` | Access requests (always need administrator approval) |
| `ANGEL_OCR_LANGUAGES` | `eng` | Tesseract languages installed in the image |
| `ANGEL_STORAGE_BACKEND` | `local` | `s3` with `ANGEL_S3_ENDPOINT_URL`, `ANGEL_S3_BUCKET`, `ANGEL_S3_REGION`, `ANGEL_S3_ACCESS_KEY_ID`, `ANGEL_S3_SECRET_ACCESS_KEY` (files are encrypted before upload) |
| Retention (`ANGEL_IMAGE_ORIGINAL_RETENTION_HOURS`, …) | see below | Deployment defaults; administrators override them in the UI |

With `ANGEL_ENV=production` (set by Compose) the application **refuses to start** with development shortcuts:
fixture connectors, the offline demo AI, the built-in scanner, the fixture face detector, insecure cookies,
optional MFA, disabled sandboxes or no Redis.

## Accounts and roles

| Role | Can |
|---|---|
| Investigator | Create investigations, collect, upload, analyze, verify, report — in investigations they are members of |
| Viewer | Read investigations they are members of |
| Supervisor | Everything an investigator can, plus approve individual-subject investigations, restricted-mode promotions, profile lookups and reverse-image searches of images with people; time-boxed oversight; abuse triage |
| Administrator | Accounts, roles, retention, legal holds, connectors, failed jobs, abuse reports, data-subject lookup, audit log — **no access to investigation content** |
| Auditor | Audit log and chain verification only |

Administration → Users: approve or disable accounts, change roles (revokes the person's other sessions), unlock,
reset MFA (the person enrols again at next sign-in) and clear refusal flags after reviewing the person's refused
requests (*Flagged* tab). Accounts are disabled rather than deleted so the audit trail stays meaningful.

## Backups

Three things must be backed up, and **the keyring must be stored separately from the other two**:

| What | Where | Contains |
|---|---|---|
| Database | volume `pgdata` | Everything structured; content columns encrypted |
| Files | volume `storage` (or the S3 bucket) | Encrypted previews, originals awaiting purge, exports |
| Keyring | volume `keys` (`keyring.json`) | KEK epochs, audit/CSRF/cursor keys, recovery-code pepper, monthly IP keys |

Without the keyring, database and file backups cannot be decrypted. With the keyring **and** a database backup,
everything in that backup can be decrypted — so never store them together, restrict who can access keyring
backups, and encrypt them (for example with `age` or GnuPG).

```bash
COMPOSE="docker compose -f deploy/docker-compose.yml"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
# Database (custom format, consistent snapshot)
$COMPOSE exec -T postgres pg_dump -U postgres -Fc angel_engine > "db-$STAMP.dump"
# Encrypted files
docker run --rm -v angel-engine_storage:/data:ro -v "$PWD":/backup alpine \
  tar czf "/backup/storage-$STAMP.tgz" -C /data .
# Keyring (to a different, more restricted location; encrypt it)
docker run --rm -v angel-engine_keys:/keys:ro alpine cat /keys/keyring.json | age -r "$KEYRING_RECIPIENT" \
  > "/secure/keyring-$STAMP.json.age"
```

Back up the keyring after every KEK rotation (the maintenance worker rotates every 30 days and records
`keys.kek_rotated` in the audit log) and after `angel-engine keys rotate`.

Choose a backup retention period and apply it consistently: deleted investigations remain recoverable from older
database backups for as long as those backups **and** the KEK epochs that wrap them exist (see *Key management*).

### Restore

1. Stop the stack: `docker compose -f deploy/docker-compose.yml down` (without `-v`).
2. Restore the keyring into the `keys` volume (it must contain the KEK epochs referenced by the database backup —
   `angel-engine keys list` shows which epochs wrap live keys).
3. Restore the files into the `storage` volume.
4. Start only PostgreSQL, then restore the database:
   ```bash
   $COMPOSE up -d postgres
   $COMPOSE exec -T postgres pg_restore -U postgres --clean --if-exists -d angel_engine < db-<stamp>.dump
   ```
   On a fresh `pgdata` volume the roles are created on first start from `deploy/secrets/`; keep the same secrets
   files you used originally (or reset role passwords with `ALTER ROLE … PASSWORD`).
5. `$COMPOSE run --rm migrate`, then `$COMPOSE up -d`.
6. Check `https://<domain>/api/v1/health/ready`, sign in, and run **Audit log → Verify chain**.

Test a restore on a separate host at least once per quarter.

## Key management

```
KEK epochs (keyring) ──wrap──▶ data keys (per investigation, per system scope) ──wrap──▶ per-file keys
```

| Command | Effect |
|---|---|
| `angel-engine keys init` | Create the keyring if it does not exist (never overwrites) |
| `angel-engine keys list` | KEK epochs, which one is active, and how many live data keys each wraps |
| `angel-engine keys rotate` | Start a new epoch and re-wrap every live data key under it (also runs automatically every 30 days) |
| `angel-engine keys destroy-kek <id>` | Destroy a retired epoch; refused for the active epoch or one that still wraps live keys |

Run them with `docker compose -f deploy/docker-compose.yml run --rm worker-analysis angel-engine keys …` so they
use the same keyring volume and maintenance credentials.

**Crypto-shredding and backups.** Deleting an investigation destroys its data key in the live database
immediately. Older database backups still contain that key, wrapped by the KEK epoch that was active when the
backup was taken. To make deletions final in backups too:

1. Keep database backups for a fixed period *B* (for example 30 days).
2. After each automatic rotation, wait until every backup taken under the previous epoch has expired (*B* days),
   then destroy that epoch with `keys destroy-kek` and delete keyring backups that still contain it.
3. Data deleted from the application is then unrecoverable after at most *B* + one rotation period.

**IP pseudonyms** use monthly keys that are destroyed automatically after 90 days, after which old pseudonyms can
no longer be linked to new ones.

**Suspected key compromise.** Rotate immediately (`keys rotate`), destroy the exposed epoch once no backup you
need depends on it, and rotate the database and Redis passwords (`FORCE=1 deploy/generate-secrets.sh`, then
`ALTER ROLE … PASSWORD` for each role and restart). If an attacker had the keyring **and** the database, treat all
content as exposed: rotating KEKs does not re-encrypt content under new data keys. System secrets (audit, CSRF,
cursor keys) are not rotated by the CLI; rotating the audit key would break verification of the existing chain.

## Retention

Purges run on the maintenance worker: image originals every 15 minutes, the retention sweep, export expiry and
session cleanup hourly, blob deletions every 10 minutes. Every purge is audited with counts only.

| Setting (Administration → Retention) | Default | Allowed range |
|---|---|---|
| Image originals after analysis | 24 h | 0–168 h (per investigation: shorter only) |
| Inactive drafts | 30 days | 1–365 |
| Refused investigation requests | 90 days | 1–365 |
| Closed → archived | 90 days | 1–3650 |
| Closed → deleted | 365 days | 1–3650 (per investigation: shorter only) |
| AI transcripts | 30 days | 1–180 |
| Screened policy text | 90 days | 1–365 |
| Audit log | 730 days | 365–2555 |
| Abuse reports | 730 days | 30–2555 |
| Report and account exports | 24 h | 1–168 h |

**Legal holds** (Administration → Investigations → *Legal hold*, step-up and reason required) pause purges and
deletion of an investigation for at most three years. Lift them as soon as the legal reason ends.

## Upgrades

```bash
$COMPOSE exec -T postgres pg_dump -U postgres -Fc angel_engine > pre-upgrade.dump   # and the keyring/files
git pull                                   # or check out the release tag
$COMPOSE build
$COMPOSE run --rm migrate                  # alembic upgrade head
$COMPOSE up -d
```

Migrations are forward-only in production; restore the pre-upgrade backup to roll back. Read the release notes
for changes to the legal documents (users will be asked to accept new versions) and to the policy rule pack.

## Monitoring

- **Health**: `GET /api/v1/health/live` (process) and `/api/v1/health/ready` (database, rate limiter, keyring;
  `503` when degraded). Container health checks cover the API, PostgreSQL, Redis and ClamAV.
- **Logs**: JSON on standard output (`docker compose logs`). Application logs carry identifiers and error types,
  never content (keys such as `query`, `email`, `prompt` or `ip` are scrubbed), and the API writes no HTTP access
  log of its own. Caddy's access log is the request log: it strips query strings, cookies and CSRF headers and
  masks client IPs.
- **Audit chain**: verified daily (`audit.chain_verified`); a failure is logged as `audit_chain_broken` with the
  first broken sequence number. Auditors can verify on demand.
- **Failed jobs**: Administration → Failed jobs lists dead jobs (after retries with backoff) with their error code;
  re-queue once the cause is fixed.
- **Capacity**: watch the `pgdata` and `storage` volumes; originals are purged automatically, previews stay for
  the life of the investigation.
- **Scanning**: if ClamAV is unhealthy, uploads queue in `scanning`; fix ClamAV rather than switching scanners.

## Abuse reports and data-subject requests

Anyone can use the public **Report abuse** form; reports are encrypted and appear under Administration → Abuse
reports (`new` → `triaging` → `actioned` or `dismissed`).

1. **Locate** — for a person asking whether they appear, use **Data-subject lookup** (step-up and a recorded
   reason): it lists the investigations and record counts in which a URL, domain, username or name occurs, without
   showing content. The value searched for is never written to the audit log.
2. **Contain** — an administrator places a **legal hold** if the material must be preserved; a supervisor can open
   a time-boxed oversight grant (reason recorded, step-up) and **suspend** the investigation.
3. **Act** — contact the investigation owner to correct or delete the material; for abuse, an administrator can
   delete the investigation with a reason (crypto-shredding).
4. **Respond** to the requester and record the outcome in the triage notes.

Accounts that collect repeated refusals are flagged automatically (3 refusals in 7 days: flagged for review; 5:
every request needs supervisor review; 8: suspended until an administrator clears the flag). Review the person's
refused requests before clearing a flag.

## From the demo to a real installation

The demo and a real installation use the same Compose project and volumes. The demo's accounts have published
passwords and TOTP secrets, so remove the demo completely before switching (production mode refuses to start while
active demo accounts exist):

```bash
make demo-reset                         # deletes the demo's containers and data (asks first)
cp deploy/.env.example deploy/.env      # ANGEL_DOMAIN, ANGEL_OPERATOR_CONTACT, API keys; on a workstation also
                                        # ANGEL_DOMAIN=localhost and ANGEL_BIND_ADDRESS=127.0.0.1
make up
docker compose -f deploy/docker-compose.yml run --rm api angel-engine create-admin --email you@org.example --name "You"
```

With `ANGEL_DOMAIN=localhost`, Caddy issues a certificate from its own local CA (the browser warns once).
Administrators cannot read investigations, so also create the people who do the work: request an account at
`/request-access` and approve it under **Administration → Users** as an investigator, and appoint a supervisor
(a different person) to approve investigations about individuals.

## Offline demo

`make demo` starts the stack on `https://localhost` with fixture connectors, the offline demo AI, the built-in
scanner and fictional `.example` data, and loads demo accounts with a fixed password and fixed TOTP secrets
printed by the seed. The demo override publishes Caddy on 127.0.0.1 only. **Never expose a demo deployment to a
network**: its credentials are public.

`seed-demo` refuses a database that already has other accounts, so running `make demo` on a real installation by
mistake never adds the demo's published accounts to it (`make up` switches back to production settings).

`make demo-stop` stops the demo and keeps its data; `make demo-reset` deletes its containers and volumes. To run
other Compose commands against the demo, pass the domain, which the demo has no `deploy/.env` for:
`ANGEL_DOMAIN=localhost docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.demo.yml logs api`.

`make up` and `make demo` first run `deploy/preflight.sh`, which stops with an explanation when this user cannot
use Docker, or when Docker already holds an Angel Engine database but this copy of the project has no
`deploy/secrets/` (a second clone or a fresh download: its new passwords would not match the existing database).

## Limits of this deployment model

- One host. Several worker replicas are safe (jobs are claimed with `SKIP LOCKED`), but the keyring file uses
  `flock` and must live on a local file system shared only by containers on that host.
- No high-availability database setup is included; use your platform's PostgreSQL backups or replication if you
  need it.
- No external KMS integration yet; the keyring is a file protected by file-system permissions and volume access.
