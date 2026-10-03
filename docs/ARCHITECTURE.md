# Architecture

Angel Engine is a single-organization, self-hosted web application: a FastAPI backend with PostgreSQL, a
PostgreSQL-backed job queue processed by two kinds of workers, and a Next.js web client, deployed behind Caddy.

```
Browser ──TLS──▶ Caddy ──/api──▶ API (FastAPI)  ───▶ PostgreSQL 16 (row-level security)
                     └──/─────▶ Web (Next.js)    ───▶ Redis (rate limits only)
                                                 ───▶ Object storage (encrypted blobs)
Job queue (PostgreSQL, SKIP LOCKED + LISTEN/NOTIFY)
  ├─ worker-analysis  queues analysis, maintenance   NO internet: uploads, page parsing, OCR, reports, purges
  └─ worker-egress    queues egress, ai              connectors (SafeHttpClient), TinEye, Vision, Claude
ClamAV (clamd, zINSTREAM) ◀── worker-analysis
```

## Components

| Component | Path | Responsibility |
|---|---|---|
| API | `backend/src/angel_engine/api/v1/` | REST endpoints, authentication, CSRF, authorization, problem+json errors |
| Domain services | `investigations/`, `evidence/`, `findings/`, `entities/`, `graph/`, `timeline/`, `notes/`, `reports/` | Business rules: lifecycle, provenance, status transitions, citations |
| Policy engine | `policy/`, `policy_gate.py` | Normalise → annotate → YAML rules → decision (allow / warn / review / refuse) + lawful alternatives |
| Sensitive-data guard | `guard/` | Detect and redact personal and secret data before anything is stored or sent |
| Image pipeline | `images/` | Validation, scanning, sandboxed decoding and analysis, sanitized previews, clues, duplicates |
| Research engine | `osint/`, `infra/http/` | Connector registry, guarded HTTP client, ingestion, corroboration and contradiction suggestions |
| AI layer | `ai/` | Context building, Claude provider (citations, structured outputs), grounding validator, proposals |
| Crypto | `crypto/` | Envelope encryption, keyring, keyed hashes (blind indexes, MACs) |
| Audit | `audit/` | Hash-chained, append-only audit log and verification |
| Jobs | `jobs/`, `*/jobs.py` | Queue, worker, scheduler, reaper, handlers |
| Retention | `retention/` | Purges, legal holds, investigation deletion, export expiry |
| Web client | `frontend/src/` | App shell, pages per investigation section, typed API client generated from OpenAPI |

## Request path

1. Caddy terminates TLS, adds HSTS and forwards `/api/*` to the API and everything else to the web server.
2. The web server renders the client application with a per-request **nonce Content-Security-Policy**
   (`frontend/src/proxy.ts`). All data is fetched client-side from `/api`.
3. The API resolves the session cookie, enforces CSRF (signed double-submit + Origin), rate limits, the role
   permission and — for investigation routes — membership and investigation state (`api/deps.py`,
   `investigation_scope`). It then sets the transaction-local row-level-security scope
   (`set_config('ae.inv_ids', …)`) so the database itself only returns that investigation's rows.
4. Business transactions write their audit events as the last statement of the same transaction, so the audit
   chain only contains committed actions.

## Background work

Jobs are rows in PostgreSQL, enqueued in the same transaction as the change that causes them and claimed with
`FOR UPDATE SKIP LOCKED`. Workers heartbeat their lease; a reaper re-queues abandoned jobs; failures retry with
exponential backoff and end in a `dead` state that administrators can re-queue. Periodic schedules (retention
sweeps, original-file purges, export expiry, audit anchoring and verification, KEK rotation) are claimed with the
same mechanism, so several worker replicas never run a slot twice.

| Queue | Worker | Network | Examples |
|---|---|---|---|
| `analysis` | worker-analysis | none (internal) | `image.scan`, `image.analyze`, `capture.parse` (page and PDF extraction), `report.export` |
| `maintenance` | worker-analysis | none (internal) | retention sweep, purges, `account.export`, audit anchor/verify, key rotation |
| `egress` | worker-egress | internet | `collection.run`, `image.public_search`, `ai.run` |

## Image analysis

`upload (raw body, ≤ 25 MiB, Idempotency-Key)` → encrypted quarantine → `image.scan` (ClamAV, fail-closed) →
`image.analyze` in a **sandboxed child process** (rlimits, single-threaded, time budgets) → decode once to
canonical pixels → hashes ∥ faces (detection only) ∥ OCR ∥ objects → redaction → **sanitized preview** (faces
and sensitive text masked, metadata stripped) → clues → duplicates → evidence, findings and graph links →
original purged after the retention window. Only the sanitized preview is ever shown or sent to a provider.

## Public-source collection

`collection run` (policy-screened query) → egress worker → connector (official API or robots-permitted page)
through `SafeHttpClient` (DNS pinning, global-IP-only policy, redirect re-validation, size caps, per-domain rate
limits, honest User-Agent) → raw records → parsing in the analysis worker's sandbox → redaction → URL
normalisation and de-duplication (keyed MACs, SimHash) → source + evidence + *source-reported / unverified*
finding → entities, relationships, facts and timeline events → corroboration/contradiction/syndication
suggestions for people to review.

## AI assistant

The assistant builds a context of evidence documents (sensitive items excluded), sends one document block per
evidence item to Claude with citations enabled (or a JSON schema for structured tasks), and validates the answer:
citations must map to supplied evidence, quoted text is re-checked, uncited sentences are labelled, unknown links
are stripped, identity claims about people in images are replaced with the face notice, and the output is
redacted. Results are stored as an interaction plus *proposals* that a person can accept as **AI hypotheses**.
There are no side-effecting tools, and evidence text is always treated as untrusted input.

## Keys and encryption

```
KEK epochs (keyring file / secret store) ──wrap──▶ per-investigation DEKs ──wrap──▶ per-object file keys
                                         └─wrap──▶ system DEKs (MFA secrets, abuse reports, policy text, exports)
```

Fields are sealed with AES-256-GCM bound to `table|column|row|investigation`; keyed hashes (URL and content MACs,
blind search tokens) derive from the investigation DEK, so destroying the DEK (investigation deletion) makes all
of its content and its search indexes unusable. See [SECURITY.md](SECURITY.md).

## Web client

Next.js 16 (App Router) with TanStack Query, Radix primitives and Tailwind. Every page is a client component that
reads the typed API (`frontend/src/lib/api/schema.d.ts`, generated from the committed `openapi.json`). Drawers and
filters are URL-driven, except free-text search terms, which never enter the URL. Report previews and other
untrusted HTML only render in `sandbox=""` iframes served by the API.
