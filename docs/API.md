# API

The REST API is served under `/api/v1` by FastAPI. The machine-readable contract is the committed OpenAPI
document [`frontend/openapi.json`](../frontend/openapi.json) (regenerate with `make openapi`); the web client's
TypeScript types are generated from it, and CI fails when the two drift apart. Interactive documentation is
disabled in production.

The API is designed for the Angel Engine web client running on the same origin. There are no API tokens: every
request is authenticated by the session cookie and protected against CSRF.

## Conventions

| Topic | Convention |
|---|---|
| Format | JSON request and response bodies (`Content-Type: application/json` is required); RFC 3339 UTC timestamps; UUID identifiers; routes have no trailing slash |
| Authentication | `__Host-ae_sid` session cookie (`HttpOnly`, `Secure`, `SameSite=Strict`). Sign-in is two steps (`auth/login` → `auth/mfa/verify`); until MFA is enrolled only the enrollment endpoints work |
| CSRF | Unsafe methods need `X-CSRF-Token` and a same-origin `Origin` header. Signed-in requests use the session's token (`__Host-ae_csrf` cookie, also returned by `GET auth/session`); anonymous forms use a fresh token from `GET auth/csrf`, which comes with its own HttpOnly `__Host-ae_form_csrf` cookie |
| Step-up | Sensitive actions return `401 reauth-required` unless the password was confirmed (`POST auth/reauth`) in the last 5 minutes |
| Pagination | Sources, evidence, findings and entities take `?limit=` (≤ 100) and `?cursor=` and return `{items, next_cursor, has_more}`; cursors are signed and bound to the filters they were issued for. Other lists are plain arrays |
| Concurrency | Investigations, findings and reports return an `ETag` (`"<version>"`). Status transitions, finding edits and report finalization require `If-Match` (`428` without it, `412` on mismatch) |
| Idempotency | `Idempotency-Key` is required for image uploads and accepted for collection runs, assistant requests and public-occurrence searches |
| Session headers | Authenticated responses carry `X-Session-Idle-Expires-In` and `X-Session-Absolute-Expires-In` (seconds). Requests with `X-Angel-Activity: background` (polling) do not extend the idle timer |
| Tracing | Every response has `X-Request-ID`; error bodies repeat it as `request_id` |
| Caching | API responses are `Cache-Control: no-store` |

## Errors

Errors are RFC 9457 `application/problem+json` objects with `type`, `title`, `status`, `code`, optional `detail`
and `request_id`. They never echo submitted values (validation errors list field locations and messages only).

| Status | `type` | Meaning |
|---|---|---|
| 400 | `/problems/bad-request` | Malformed request |
| 401 | `/problems/unauthenticated`, `/problems/mfa-required`, `/problems/reauth-required` | Sign in, finish MFA, or confirm the password |
| 403 | `/problems/forbidden`, `/problems/csrf-failed` | Role or membership does not allow the action; CSRF/Origin check failed |
| 404 | `/problems/not-found` | Not found **or no access** (existence of investigations is never revealed) |
| 409 | `/problems/conflict`, `/problems/conflict-state` | Duplicate, or not allowed in the current state (bodies list `allowed_transitions` / `failed_preconditions` where relevant) |
| 409 | `/problems/policy-acknowledgement-required` | A *warn* policy decision: show the notices and resubmit with `acknowledge_policy_notices: true` |
| 411 / 413 / 415 | `/problems/length-required`, `/problems/payload-too-large`, `/problems/unsupported-media` | Upload checks |
| 412 / 428 | `/problems/precondition-failed`, `/problems/precondition-required` | `If-Match` mismatch / missing |
| 422 | `/problems/validation-error` | Invalid fields |
| 422 | `/problems/policy-refused` | The Acceptable Use Policy refuses the request (see below) |
| 429 | `/problems/rate-limited` | Rate limit; honour `Retry-After` |
| 503 | `/problems/service-unavailable` | A required service (scanner, AI provider, Redis for fail-closed limits) is unavailable |

### Policy decisions

Purposes, collection queries and parameters, assistant prompts, AI-suggested queries, image notes and custom
report sections are screened. Outcomes:

- **allow** — the request proceeds.
- **warn** — `409 policy-acknowledgement-required` with the notices; resubmit with the acknowledgement flag.
- **review** — the request is stored as `pending_review` (for example, a collection run or a new investigation
  about an individual) and a supervisor decides.
- **refuse** — `422 policy-refused`:

```json
{
  "type": "/problems/policy-refused",
  "title": "Angel Engine can't help with this request",
  "status": 422,
  "code": "policy_refused",
  "detail": "Home and residential addresses of individuals are private, so Angel Engine does not search for them.",
  "policy": {
    "decision_id": "0199a1f0-…",
    "decision": "refuse",
    "categories": ["home_address"],
    "rule_ids": ["HA-001", "HA-002", "IS-003"],
    "rule_pack_version": "2026.10.0",
    "rationale": "Home and residential addresses of individuals are private, so Angel Engine does not search for them.",
    "alternatives": [
      {
        "kind": "connector",
        "label": "Look up the registered business address of an organization in a company registry",
        "template": "registered office address of {organization}",
        "connector_id": "gleif"
      },
      {"kind": "guidance", "label": "Review the Acceptable Use Policy for the lawful purposes Angel Engine supports"}
    ],
    "notices": []
  },
  "request_id": "6f1c…"
}
```

The refused text is never echoed back; it is stored encrypted with a system key and deleted after 90 days.

`POST policy/preflight` runs the same screening without side effects (used by the New Investigation wizard).

## Endpoints

`{I}` = `/api/v1/investigations/{investigation_id}`. Investigation routes require membership (or an oversight
grant) in addition to the role permission; see [SECURITY.md](SECURITY.md#authorization).

### Public

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/health/live`, `/api/v1/health/ready` | Liveness; readiness (database, rate limiter, keyring) |
| GET | `/api/v1/auth/csrf` | CSRF token for anonymous forms |
| POST | `/api/v1/auth/login` | Password step (identical errors for every failure) |
| POST | `/api/v1/auth/registration-requests` | Request an account (an administrator approves) |
| GET | `/api/v1/legal/documents/current` | Current Terms, Privacy Policy, Acceptable Use Policy, Responsible Use |
| POST | `/api/v1/abuse-reports` | Report abuse, a data-removal request or a vulnerability |
| POST | `/api/v1/security/csp-reports` | Content-Security-Policy violation reports (rate-limited, content-free logging) |

### Account and session

| Method | Path | Purpose |
|---|---|---|
| POST | `auth/mfa/verify` | TOTP or recovery code |
| POST | `auth/mfa/enroll`, `auth/mfa/enroll/confirm` | Mandatory TOTP enrollment (QR code as a data URI + recovery codes) |
| POST | `auth/mfa/recovery-codes` | Regenerate recovery codes (step-up) |
| POST | `auth/reauth` | Confirm the password for step-up actions |
| PUT | `auth/password` | Change password (revokes other sessions) |
| POST | `auth/logout` | End the session |
| GET | `auth/session` | Current user, CSRF token, expiry |
| GET, PATCH | `me` | Profile and preferences (theme, density) |
| POST | `me/attestations` | Accept the current legal documents |
| GET, DELETE | `me/sessions`, `me/sessions/{id}` | List and revoke sessions |
| GET | `me/policy-decisions` | The person's own policy decisions with explanations |
| POST, GET | `me/data-exports` | Request (step-up) and list account exports |
| GET | `me/data-exports/{id}/download` | Single-use download (step-up) |

### Investigations

| Method | Path | Purpose |
|---|---|---|
| GET, POST | `/api/v1/investigations` | List own investigations (incl. refused requests); create (purpose, lawful basis, attestations, policy screening) |
| GET | `/api/v1/investigations/by-ref/{ref}` | Resolve a display reference (membership still required) |
| GET, PATCH | `{I}` | Summary and permissions; edit title/description/AI setting |
| POST | `{I}/submit`, `{I}/review` | Submit for supervisor review; approve or reject (a supervisor other than the requester) |
| POST | `{I}/suspend`, `{I}/resume`, `{I}/close`, `{I}/reopen`, `{I}/archive`, `{I}/restore` | Lifecycle |
| POST | `{I}/deletion` | Delete and crypto-shred (owner or administrator for abuse handling; step-up, typed reference, reason) |
| GET | `{I}/dashboard`, `{I}/activity` | Overview widgets; investigation audit trail |
| GET, POST, PATCH, DELETE | `{I}/members`, `{I}/members/{user_id}` | Membership (owner) |
| POST | `{I}/oversight-grants` | Time-boxed supervisor read-only access |
| GET, PUT | `{I}/retention` | Per-investigation retention within platform limits |
| PUT | `{I}/legal-hold` | Legal hold (administrator, step-up) |

### Collection, sources and evidence

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/connectors`, `{I}/connectors` | Connector catalog and status (ready / needs key / disabled / not available in restricted mode) |
| GET, POST | `{I}/collection-runs` | List; start a run (policy-screened, `202`) |
| GET | `{I}/collection-runs/{run}` | Progress and counts |
| POST | `{I}/collection-runs/{run}/cancel`, `/approve`, `/reject` | Cancel; supervisor decision for runs pending review |
| GET | `{I}/collection-runs/{run}/leads` | Transient search-engine leads (not stored as evidence) |
| POST | `{I}/captures` | Capture selected leads or URLs (robots-permitted pages only) |
| GET | `{I}/manual-search-links` | Search URLs the investigator opens themselves (no automated scraping) |
| GET, PATCH | `{I}/sources`, `{I}/sources/{source}` | Sources; reliability and notes |
| GET, POST | `{I}/evidence` | Filtered evidence list; manual capture (quoted excerpt + URL) |
| GET, PATCH, DELETE | `{I}/evidence/{evidence}` | Detail; annotations (content is immutable); deletion (step-up) |

Filters (query parameters, combined with AND):

- `evidence`: `source_id`, `image_id`, `evidence_type`, `provenance`, `category`, `domain`, `captured_from`/`_to`,
  `published_from`/`_to`, `country`, `region`, `flagged`, `q`.
- `findings`: `status`, `provenance`, `category`, `confidence`, `importance`, `source_id`, `source_category`,
  `domain`, `connector`, `evidence_type`, `entity_id`, `captured_from`/`_to`, `published_from`/`_to`, `country`,
  `region`, `has_contradictions`, `include_retracted`, `q`, `sort`.

`q` is matched against keyed search tokens (exact terms, AND); `country` and `region` are ISO 3166 codes.

### Findings, graph and timeline

| Method | Path | Purpose |
|---|---|---|
| GET, POST | `{I}/findings` | List; create an analyst finding (must cite evidence) |
| GET, PATCH | `{I}/findings/{f}` | Detail; edit (`If-Match`) |
| GET | `{I}/findings/{f}/allowed-transitions` | Target statuses with their failed preconditions |
| POST | `{I}/findings/{f}/transitions` | Change verification status (justification, cited evidence, `If-Match`) |
| POST | `{I}/findings/{f}/retract` | Retract (`If-Match`) |
| GET | `{I}/findings/{f}/history` | Full provenance and status trail |
| POST, PATCH, DELETE | `{I}/findings/{f}/evidence-links(/{link})`, `…/dismiss` | Link evidence with a stance; dismiss contradictions with a reason |
| GET | `{I}/suggestions`; POST `…/{s}/accept`, `…/{s}/dismiss` | Corroboration, contradiction, syndication and duplicate suggestions |
| GET, POST | `{I}/entities`, `{I}/entities/{e}`, `…/merge` | Entities |
| GET, POST | `{I}/relationships`, `{I}/relationships/{r}`, `…/evidence`, `…/transitions` | Relationships (every edge cites evidence) |
| GET | `{I}/graph?root=&depth=&status=&rel_type=&entity_type=`, `{I}/graph/path` | Subgraph (depth ≤ 3); path between two entities |
| GET, POST, DELETE | `{I}/timeline-events(/{event})`, `…/status` | Timeline |
| GET, POST, PATCH, DELETE | `{I}/notes(/{note})` | Notes (policy-screened) |
| GET | `{I}/search`, `/api/v1/search` | Keyword search in one or all of the person's investigations |

### Images

| Method | Path | Purpose |
|---|---|---|
| POST | `{I}/images` | Upload one image as the raw body (`Content-Type: image/*`, `Content-Length`, `Idempotency-Key`, optional URL-encoded `X-Filename`) |
| GET | `{I}/images`, `{I}/images/{m}` | Status, file information, generalized metadata, hashes, analyses; `notices` contains the face notice when faces were detected |
| GET | `{I}/images/{m}/preview` | Sanitized preview (faces and sensitive text blurred, metadata stripped). Originals are never served |
| GET | `{I}/images/{m}/clues`, `{I}/images/{m}/similar` | Visual clues; duplicates and similar images within the person's investigations |
| POST | `{I}/images/{m}/clues/{c}/promote`, `…/pivot` | Promote a clue to evidence; start a collection run from it |
| POST | `{I}/images/{m}/reverse-search-approval` | Supervisor approval for images with faces or people |
| POST | `{I}/images/{m}/public-occurrence-search` | TinEye / Google Cloud Vision / Claude vision on the sanitized preview (gated) |
| DELETE | `{I}/images/{m}?scope=file\|all` | Delete the files only, or the image with everything derived from it (step-up) |

### Assistant

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/assistant/status` | Whether AI is available, provider, model and label (for example "offline demo AI") |
| POST, GET | `{I}/assistant/requests` | Ask (task + question + optional evidence selection, `202`); list |
| GET | `{I}/assistant/requests/{a}` | Validated answer: segments with citations, uncited labels, grounding status |
| GET | `{I}/assistant/proposals`; POST `…/{p}/accept`, `…/{p}/reject` | AI proposals; accepted items become AI hypotheses |

### Reports

| Method | Path | Purpose |
|---|---|---|
| GET, POST | `{I}/reports` | List; create a draft from verified data |
| GET, PATCH, DELETE | `{I}/reports/{p}` | Detail (structured document); edit options and sections (`If-Match`); delete drafts |
| POST | `{I}/reports/{p}/refresh` | Rebuild from current data |
| GET | `{I}/reports/{p}/preview` | Self-contained HTML for a `sandbox=""` iframe |
| POST | `{I}/reports/{p}/finalize` | Lock, hash and anchor in the audit log (`If-Match`) |
| GET, POST | `{I}/reports/{p}/exports` | HTML, Markdown, JSON or PDF export (step-up) |
| GET | `{I}/reports/{p}/exports/{x}/download` | Download (step-up, 24 h) |

### Supervision, administration and audit

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/reviews` | Investigations awaiting supervisor review (collection runs pending review are decided per investigation) |
| GET | `/api/v1/admin/users`; PATCH `…/{u}`; POST `…/{u}/approve`, `/disable`, `/enable`, `/unlock`, `/reset-mfa`, `/clear-flag` | Accounts and roles |
| GET | `/api/v1/admin/flags` | Accounts flagged by repeated refusals |
| GET | `/api/v1/admin/investigations` | Metadata-only register (reference, status, owner, dates) |
| GET, PATCH | `/api/v1/admin/settings/retention` | Retention defaults within hard limits |
| GET | `/api/v1/admin/jobs`; POST `…/{j}/requeue` | Background jobs and dead letters |
| GET, PATCH | `/api/v1/admin/abuse-reports(/{r})` | Abuse and data-subject request triage |
| POST | `/api/v1/admin/data-subject-lookup` | Locate where a URL, domain, username or name occurs, without content (step-up, reason required) |
| GET | `/api/v1/audit-events`, `/api/v1/audit-events/verify` | Audit log and chain verification (administrators, auditors) |

## Example: sign in and list investigations

```bash
ORIGIN=https://angel.example.org BASE=$ORIGIN/api/v1 JAR=$(mktemp)
CSRF=$(curl -s -c "$JAR" "$BASE/auth/csrf" | jq -r .csrf_token)
# The login response belongs to the new (MFA-pending) session and carries that session's CSRF token.
CSRF=$(curl -s -b "$JAR" -c "$JAR" -H "Origin: $ORIGIN" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' \
       -d '{"email":"you@org.example","password":"…"}' "$BASE/auth/login" | jq -r .csrf_token)
curl -s -b "$JAR" -c "$JAR" -H "Origin: $ORIGIN" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' \
     -d '{"code":"123456"}' "$BASE/auth/mfa/verify" > /dev/null
curl -s -b "$JAR" "$BASE/investigations" | jq '.[] | {ref, title, status}'
```

Scripted access is meant for operators testing their own deployment; investigation work belongs in the web
client, where notices, refusals and step-up prompts are shown to the person doing the work.
