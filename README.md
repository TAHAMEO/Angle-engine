# Angel Engine

**Angel Engine** is a lawful, privacy-first OSINT (open-source intelligence) investigation platform. It helps
authorized investigators — journalists, fact-checkers, due-diligence and trust-and-safety teams — collect, organize,
verify and report on **publicly available** information.

It is deliberately **not** a people-search or facial-recognition service.

> *Investigate public evidence, verify sources, protect privacy, and never turn an AI inference into an identity
> claim.*

## What it does

- **Image investigation with non-biometric evidence only** — file checks and malware scanning, metadata analysis
  (GPS generalized to region level, serial numbers removed), OCR of visible text with sensitive-data redaction,
  perceptual hashes and duplicate detection, object detection and clues (domains, usernames, hashtags, signs,
  organizations, landmarks). Faces are only *detected* so they can be blurred:
  *"A face was detected in the image. Angel Engine does not perform facial identification."*
- **Public-source research through compliant connectors** — web pages that allow automated access, web archives,
  domain registration and certificate-transparency data, DNS, news indexes, company and government registries,
  public profiles, forums, image sources and (with a key) Brave Search, TinEye and Google Cloud Vision. Connectors
  never log in, solve CAPTCHAs, bypass paywalls or query people-search or breach sources.
- **Evidence management** — every result reads
  **Source → Finding → Evidence → Timestamp → Confidence → Verification Status**, with immutable provenance
  (observed, source-reported, analyst inference, AI hypothesis) and audited, human-only status changes that are
  checked against preconditions (for example, *corroborated* needs two independent origins).
- **Relationship graph and timeline** in which every edge and event carries the evidence behind it.
- **Source-grounded AI assistant** (Claude, optional): answers cite evidence; uncited text is labelled; when the
  evidence is not enough it answers *"Insufficient public evidence to establish this conclusion."* AI output is
  stored only as proposals and hypotheses until a person verifies it.
- **Cited reports** in HTML, Markdown, JSON and PDF; finalized reports are locked, hashed and anchored in the
  audit log.

## Safety and privacy by design

- Every investigation records a purpose, a lawful basis and attestations; an acceptable-use **policy engine**
  refuses doxxing, stalking, location tracking, face identification, private-contact and sensitive-attribute
  requests and suggests lawful alternatives.
- Investigations about an **individual** need a supervisor's approval (not the requester's) and then run in
  **restricted mode**.
- Sensitive data (cards, IBANs, national IDs, secrets, private contact details, street addresses, …) is
  **redacted before storage**; investigation content is encrypted with a per-investigation key, and deleting an
  investigation **crypto-shreds** it.
- A **hash-chained audit log**, retention controls, legal holds, export-my-data and a public abuse/data-request form.

See [`docs/`](docs/) for the full picture: [architecture](docs/ARCHITECTURE.md), [security](docs/SECURITY.md),
[threat model](docs/THREAT_MODEL.md), [privacy](docs/PRIVACY.md), [data model](docs/DATA_MODEL.md),
[API](docs/API.md), [connectors](docs/CONNECTORS.md), [operations](docs/OPERATIONS.md) and
[responsible use](docs/RESPONSIBLE_USE.md).

## Quick start

### Offline demo with Docker

```bash
make demo        # generates secrets, builds the images, starts https://localhost and loads the demo data
```

The demo uses recorded connector responses, an offline demo AI and fictional `.example` data. Sign in at
`https://localhost` (accept Caddy's local certificate) with `investigator@angel-engine.example` and the password
and TOTP secret printed by the seed (add the secret to any authenticator app). Other demo accounts: supervisor,
viewer, admin and auditor.

### Local development

Requirements: Python ≥ 3.11, Node.js 22 + pnpm 10, PostgreSQL 16, Redis, Tesseract OCR (+ Pango for PDF reports).

```bash
make setup services migrate      # virtualenv, local PostgreSQL (port 54329) + Redis (63799), schema
export ANGEL_CONNECTOR_MODE=fixtures ANGEL_AI_PROVIDER=fake ANGEL_SCANNER=builtin \
       ANGEL_FACE_DETECTOR=fixture ANGEL_COOKIE_SECURE=false
make seed-demo                   # optional: demo users and an investigation
make api                         # FastAPI on :8000      (separate terminals)
make worker                      # background jobs
make web-install web-dev         # Next.js on http://localhost:3000
```

Checks: `make lint typecheck test` (backend), `make web-check` (web), `make compose-config` (deployment).

### Production

```bash
cp deploy/.env.example deploy/.env    # set ANGEL_DOMAIN and optional API keys
make up                               # secrets, images, migrations, TLS via Caddy
docker compose -f deploy/docker-compose.yml run --rm api angel-engine create-admin --email you@org --name "You"
```

Read [operations](docs/OPERATIONS.md) before going live (backups, key handling, retention, upgrades).

## Repository layout

```
backend/    FastAPI API, job worker, image pipeline, connectors, policy engine, AI layer, reports (Python)
frontend/   Next.js web application (TypeScript), Vitest component tests
deploy/     Docker Compose, Dockerfiles, Caddy, ClamAV, PostgreSQL initialisation, secrets generator
docs/       Architecture, security, threat model, privacy, data model, API, connectors, operations, responsible use
scripts/    Development helpers (local PostgreSQL/Redis, data builders)
```

## Legal

The legal texts in `backend/src/angel_engine/legal/` (Terms of Use, Privacy Policy, Acceptable Use Policy,
Responsible Use) are templates and **must be reviewed by counsel** before production use. Third-party components
and their licences are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
