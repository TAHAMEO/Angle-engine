# Security

This document describes the security controls as implemented. Report vulnerabilities through the in-product
**Report abuse** form (category *Security vulnerability*) or to your administrator; please do not open public
issues for vulnerabilities.

## Authentication and sessions

- **Passwords**: Argon2id (argon2-cffi, RFC 9106 profile), 12–128 characters, checked against a common-password
  list and the person's name/e-mail; no forced rotation; hashing runs in a bounded thread pool; unknown e-mail
  addresses get a dummy verification so timing does not reveal accounts. Identical error messages for every
  failure.
- **Multi-factor authentication is mandatory for every role**: TOTP (SHA-1, 6 digits, 30 s, ±1 step) with replay
  protection (a time step can be used once), 10 single-use recovery codes stored as keyed hashes. Until enrolled,
  a session can only reach the enrollment endpoints.
- **Sessions** are server-side: a random 32-byte token in an `HttpOnly`, `Secure`, `SameSite=Strict`
  `__Host-ae_sid` cookie, stored only as a SHA-256 hash. Idle timeout 30 minutes, absolute limit 12 hours, at most
  five sessions per person; tokens rotate on sign-in, MFA and privilege changes; password, MFA and role changes
  revoke other sessions. Background polling (`X-Angel-Activity: background`) never extends the idle timer. The web
  client warns two minutes before expiry.
- **Step-up authentication**: sensitive actions require a password confirmation within the last five minutes
  (signing in counts): deleting images, evidence or investigations, report exports and downloads, account data
  exports, recovery-code regeneration, role changes, legal holds and the data-subject lookup.
- **Lockout**: five failures lock the account for 15 minutes, doubling up to 24 hours; per-IP limits apply in
  addition. New accounts must be approved by an administrator.

## Request integrity

- **CSRF**: signed double-submit token (`__Host-ae_csrf` cookie + `X-CSRF-Token` header, HMAC with a per-session
  key; a server-keyed token for anonymous forms) plus an exact `Origin` check (falling back to `Sec-Fetch-Site`).
  Request bodies must be JSON (uploads use a raw image body).
- **Concurrency**: mutable resources use `ETag`/`If-Match`; verification-status changes and report finalization
  require it. Uploads, collection runs and assistant requests accept an `Idempotency-Key`.
- **Rate limits** (Redis GCRA; the ones marked fail closed reject requests when Redis is unavailable):

  | Limit | Rate | Fail closed |
  |---|---|---|
  | Sign-in per account / per IP | 5 / min · 20 / min | yes |
  | MFA verification per account | 5 / 5 min | yes |
  | Access requests per IP · abuse reports per IP | 3 / h · 5 / h | yes |
  | Reads · writes per person | 300 / min · 60 / min | no |
  | Uploads per person | 20 / h and 500 MiB / day | yes |
  | Collection runs | 30 / h per person, 300 / day per investigation | yes |
  | Assistant requests | 30 / h per person + daily token budget | yes |
  | Report and account exports | 10 / h per person | yes |

## Authorization

- Roles: **admin**, **supervisor**, **investigator**, **viewer**, **auditor**. Investigation access requires both a
  role permission and membership (owner, editor, viewer) or a time-boxed (≤ 72 h), audited, read-only supervisor
  oversight grant. Investigation state also matters (a pending-review or closed investigation is read-only).
- **Administrators administer but cannot read investigation content**; auditors read the audit log only.
- Non-members always get `404` (existence is not revealed), and the denial is audited in a separate transaction.
- Every API route is either authenticated or explicitly marked public; a test walks all routes to enforce it.
- **PostgreSQL row-level security** on every investigation-scoped table, keyed on a transaction-local scope set
  only after the authorization check. The application connects as non-owner roles (`ae_app`, `ae_worker`);
  only the maintenance role used by purges, key rotation and other content-free maintenance bypasses RLS.
- Separation of duties: individuals as subjects need a supervisor who is not the requester; in restricted mode,
  promotions to *confirmed* or *corroborated* must be made by a supervisor who did not create the finding;
  reverse-image searches of images with faces or people need a supervisor who did not upload the image.

## Data protection

- **Envelope encryption**: KEK epochs in the keyring wrap per-investigation data keys, which wrap per-object file
  keys. Content fields use AES-256-GCM with associated data `ae1|table|column|row|investigation`, so ciphertext
  cannot be moved between rows. Blobs (originals, previews, exports) are encrypted before they reach storage.
- **Crypto-shredding**: deleting an investigation destroys its data keys; everything encrypted with them,
  including keyed search indexes, becomes unreadable at once. Backups stay decryptable only until their KEK epoch
  is destroyed (see [OPERATIONS.md](OPERATIONS.md)).
- **Keyed hashes** (URL/content MACs, SimHash, blind search tokens) derive from the investigation key, so
  de-duplication and search work without plaintext and die with the key.
- **Redaction before storage**: payment cards (Luhn + IIN), IBANs, national identifiers, secrets and tokens
  (cloud keys, GitHub/Slack/Stripe/Anthropic tokens, JWTs, PEM keys, `password=` pairs), URL credentials and token
  parameters, e-mail addresses of named people, phone numbers, street addresses of people, dates of birth, MRZ
  lines and Wi-Fi QR payloads. Medical terms are flagged and hidden by default.
- **Audit log**: append-only (UPDATE/DELETE/TRUNCATE blocked by triggers), every row chained with
  `HMAC(audit_key, previous_hash ‖ canonical record)`, daily anchoring and verification, content-free details,
  monthly-rotated IP pseudonyms. Auditors can verify the chain from the UI.

## Untrusted input

- **Uploads**: raw-body upload with `Content-Length` ≤ 25 MiB, magic-byte checks, polyglot rejection (ZIP, PDF,
  PE, HTML/PHP trailers), malware scanning with ClamAV before any processing (fail closed), decoding in a sandboxed
  child process with memory/CPU/file-size limits and an allowlist of formats, pixel-count limits against
  decompression bombs. Originals are never served; only sanitized previews are, with `CSP: sandbox`.
- **Outbound requests (SSRF)**: only the egress worker can reach the internet, only through `SafeHttpClient`:
  DNS resolved once and pinned, every address must be globally routable (IPv4-mapped, 6to4, Teredo and NAT64
  forms unwrapped; private, loopback, link-local, reserved and multicast refused), redirects re-validated, ports
  80/443 only, no credentials/cookies/Referer, size and time caps, robots.txt honoured, per-domain rate limits.
- **Captured pages and PDFs** are parsed in a sandboxed child process on the analysis worker, which has no
  network access.
- **Prompt injection**: evidence is passed to Claude as delimited documents; the assistant has no tools that change
  anything; every answer is validated (citations must match supplied evidence, unknown URLs are stripped, identity
  claims about people in images are replaced, output is redacted) and stored only as proposals.

## Browser security

- Web pages: per-request nonce CSP (`script-src 'nonce-…' 'strict-dynamic'`, `style-src 'self' 'nonce-…'`,
  `object-src 'none'`, `base-uri 'none'`, `frame-ancestors 'none'`, `connect-src 'self'`), `Referrer-Policy:
  no-referrer`, `nosniff`, COOP/CORP, `X-Frame-Options: DENY`, restrictive `Permissions-Policy`, `noindex`.
- API responses: `CSP: default-src 'none'; frame-ancestors 'none'`, `nosniff`, `no-referrer`, COOP/CORP,
  `Cache-Control: no-store`, HSTS. Report previews are framed only by the app (`frame-ancestors 'self'`) inside
  `sandbox=""` iframes, with their own `sandbox; default-src 'none'` policy.
- No third-party scripts, fonts, analytics, map tiles or CAPTCHAs. AI output and evidence are rendered as text,
  never as HTML; a lint rule forbids `dangerouslySetInnerHTML` and `innerHTML`. Links to sources open with
  `noopener noreferrer`, show punycode host names and warn that the site will see the visitor's IP address.

## Deployment hardening

Containers run as non-root users with read-only root file systems, all capabilities dropped and
`no-new-privileges`. Only Caddy is published; the analysis worker has no route to the internet. Database
passwords and connection URLs are Docker secrets; the keyring lives on a dedicated volume and must be backed up
separately from database backups. Production settings refuse development shortcuts (fixture connectors, the
offline demo AI, the built-in scanner, insecure cookies, disabled MFA or sandboxes).
