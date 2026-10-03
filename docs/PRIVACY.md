# Privacy

Angel Engine is built to investigate public evidence while minimising the personal data it touches. This page
explains what is stored, for how long, who can see it and what leaves the system. The customer-facing Privacy
Policy template is in `backend/src/angel_engine/legal/privacy.md` (to be reviewed by counsel).

## Principles

1. **Purpose first** — every investigation records a purpose, a lawful basis and attestations; requests are
   screened against the Acceptable Use Policy before anything runs.
2. **Collect less** — connectors use official APIs and pages that allow automated access; search results are
   transient leads, and only pages a person selects are captured.
3. **Redact before storing** — sensitive values are replaced by placeholders and only per-type counts are kept.
4. **No biometrics** — faces are detected only to blur them; nothing infers identity, age, gender, ethnicity,
   emotion or other sensitive attributes.
5. **Generalise locations** — GPS coordinates become country and region; exact coordinates are never stored.
6. **Encrypt and expire** — content is encrypted with a per-investigation key, kept only as long as configured,
   and destroyed by deleting that key.

## What is stored

| Data | Where | Protection | Default retention |
|---|---|---|---|
| Account (e-mail, name, role, password hash, MFA secret, recovery-code hashes) | `users`, `recovery_codes` | MFA secret encrypted; codes hashed | Lifetime of the account (accounts are disabled, not erased, so the audit trail stays intact) |
| Sessions (browser family, timestamps, monthly IP pseudonym) | `user_sessions` | Token stored as SHA-256 | 7 days after expiry |
| Investigation purpose, authorization reference, review notes | `investigations` | Encrypted (investigation key) | Life of the investigation |
| Sources, evidence excerpts, findings, notes, entities, reports | investigation tables | Encrypted; keyed hashes for search | Life of the investigation |
| Uploaded image originals | object storage | Encrypted per object | **24 h after analysis** (0–168 h, configurable per investigation within the platform maximum) |
| Sanitized previews, hashes, analysis results, clues | object storage / tables | Encrypted | Life of the investigation |
| AI transcripts (prompt and answer) | `ai_interactions` | Encrypted | 30 days (accepted proposals stay as AI hypotheses) |
| Screened request text (policy decisions) | `policy_decisions` | Encrypted (system key) | 90 days; decision metadata 1 year |
| Report and account exports | object storage | Encrypted per object | 24 hours; account exports are deleted after the single download |
| Audit log | `audit_log` | Append-only, hash-chained, no content | 2 years (365 days–7 years) |
| Abuse and data-subject requests | `abuse_reports` | Description and contact encrypted (system key) | 2 years |

Investigations: inactive drafts are deleted after 30 days; refused investigations after 90 days; closed
investigations are archived after 90 days and deleted after 365 days, with notice, unless a legal hold applies.
Administrators can change these values within hard limits (Administration → Retention).

## What is redacted

Before storage (and before anything is sent to an AI or vision provider): payment card numbers, IBANs, national
identity numbers, passport and machine-readable-zone lines, secrets and API tokens, credentials and token
parameters in URLs, e-mail addresses of named people (role mailboxes such as `press@` are kept; free-mail
addresses are fully removed), phone numbers (except organizational and toll-free numbers in context), dates of
birth, street addresses of people (organizational addresses from registries are kept at city level), vehicle
plates (with context), Wi-Fi network credentials in QR codes. Medical terms mark an item as sensitive: it is hidden
by default and excluded from AI context. **Restricted mode** (investigations of individuals) removes all
contact and location details.

Images: EXIF serial numbers, owner and artist names, host names and unique identifiers are replaced by a
presence flag; GPS becomes country/region; faces and sensitive text regions are blurred in the preview; the
original is deleted after analysis.

## Who can see what

- **Investigation members** see that investigation's content according to their membership (owner, editor,
  viewer). Nobody else does — including administrators.
- **Supervisors** see investigations awaiting their review, and can obtain a time-boxed, audited, read-only
  oversight grant.
- **Administrators** manage accounts, retention and legal holds and see investigations only as metadata
  (reference, status, owner, dates). Their data-subject lookup tells them *where* a URL, domain, username or name
  occurs, never the content.
- **Auditors** see the audit log, which never contains content.

## What leaves the system

Only when configured, and only for the investigation's own purposes:

| Recipient | What is sent | When |
|---|---|---|
| Public sources (APIs, web pages) | The query or URL; an honest User-Agent with a contact page | Collection runs a person starts |
| Anthropic (Claude) | Redacted evidence excerpts and the question; sanitized image previews for vision clues | Assistant requests, if the investigation allows AI |
| Google Cloud Vision / TinEye | The sanitized preview (faces and sensitive text blurred) | A person starts a public-occurrence search, subject to the face/person gate |
| Brave Search | The search query | Keyword searches with the Brave connector |

Providers' own terms and retention apply. Angel Engine never sends originals, faces, credentials or raw OCR text.

## Rights and requests

- **Access / portability (account holders)**: Privacy & Data Controls → *Export my data* (ZIP of account data,
  sessions, attestations, policy decisions, memberships and own audit entries).
- **Investigation content** is exported by members as cited reports.
- **People who appear in public sources**: the public *Report abuse* form (category *Data removal request* or
  *I am targeted by an investigation*). Administrators locate references with the data-subject lookup, contact the
  investigation owner, and can place a legal hold or delete an investigation for abuse handling.
- **Deletion**: owners delete investigations (crypto-shredding); image files or whole images with everything
  derived from them can be deleted individually.
