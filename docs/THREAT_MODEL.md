# Threat model

Angel Engine handles information about real organizations and, sometimes, real people. The most important threat
is **misuse by its own users** — turning an OSINT tool into a stalking, doxxing or surveillance tool — followed by
the usual threats to a web application that stores sensitive data.

## Assets

| Asset | Why it matters |
|---|---|
| Collected evidence, notes, findings, reports | May contain personal data of third parties; confidential work product |
| Uploaded images and derivatives | May show people, places and identifying details |
| Investigation purposes, authorization references | Reveal what an organization is investigating |
| Accounts, sessions, MFA secrets | Access to everything above |
| Keyring (KEKs, system secrets) | Decrypts all content; defines what crypto-shredding can destroy |
| Audit log | Accountability; evidence of misuse |

## Actors

- **Authorized investigator acting in bad faith** (stalking, doxxing, harassment, discrimination).
- **Curious or careless insider** (reading investigations they are not part of, exporting too much).
- **Administrator** (powerful by design, but should not read investigation content).
- **External attacker** (account takeover, injection, SSRF, malware uploads, data exfiltration).
- **Hostile content** (malicious files, pages crafted for prompt injection or parser exploits, tracking pixels).
- **Data subjects and the public** (need a way to ask whether and how they appear).

## Threats and mitigations

| Threat | Mitigations |
|---|---|
| Finding a private person's home, location or contacts | Policy engine refuses (home address, location tracking, private contact info, doxxing categories) on purposes, queries, assistant prompts, notes and report sections, with lawful alternatives; redaction of addresses, phones and e-mails before storage; GPS generalized to region; no people-search or breach connectors; restricted mode for individual subjects |
| Identifying people from photos | No face recognition, embeddings or demographic inference anywhere (a CI check forbids such libraries); faces only detected and blurred; required face notice; AI vision post-filters person names; reverse-image search of images with faces needs a separate supervisor's recorded approval and is never available in restricted mode |
| Turning AI guesses into facts | AI output is stored as proposals; accepted items carry the permanent *AI hypothesis* provenance; uncited text is labelled; insufficient evidence yields the fixed answer; statuses change only through human, justified, precondition-checked transitions |
| Investigating an individual without basis | Mandatory purpose, lawful basis and attestations; supervisor approval by someone other than the requester; restricted mode (stricter redaction, no contact or location data, limited connectors, second approver) |
| Repeated probing for forbidden data | Refusals are recorded; within seven days, three refusals flag the account for administrator review, five route all of its requests to supervisor review, and eight suspend it until an administrator clears the flag |
| Insider reading other investigations | Membership-based authorization plus database row-level security; non-members get 404; oversight grants are time-boxed and audited; administrators have no content permissions |
| Over-retention | Retention defaults with administrator maxima, automatic purges of originals (24 h), drafts, refused-request text, AI transcripts and exports; deletion crypto-shreds; legal holds are explicit and audited |
| Account takeover | Mandatory TOTP, lockout and rate limits, Argon2id, strict session cookies, step-up re-authentication, session listing and revocation |
| CSRF / XSS / clickjacking | Signed double-submit CSRF + Origin checks; nonce CSP with `strict-dynamic`; no HTML rendering of untrusted content; sandboxed iframes for report previews; `frame-ancestors 'none'` |
| SSRF through connectors or URLs | Only the egress worker has internet access, only via `SafeHttpClient` (pinned DNS, global-address policy, redirect re-validation, port allowlist, caps) |
| Malicious uploads and parser exploits | Size limits, magic-byte and polyglot checks, ClamAV (fail closed), sandboxed decoding with resource limits, analysis worker without network, only re-encoded previews served |
| Prompt injection via evidence | Delimited documents, no side-effecting tools, validation of citations/URLs/identity claims, redaction of output, proposals instead of writes |
| Tampering with the record | Hash-chained, append-only audit log with daily anchors and verification; final reports locked by a database trigger and hashed; evidence content immutable |
| Key compromise or loss | KEK epochs with rotation; keyring separate from database backups; per-investigation data keys limit blast radius; documented backup and destruction procedure |
| Data-subject requests | Public request form; administrator lookup that locates references by keyed hashes without reading content; legal hold or deletion for abuse handling; export-my-data for account holders |

## Residual risks and limits

- A determined insider can still copy what they are allowed to see (screenshots, manual notes). The audit log
  records their actions; it does not prevent copying.
- The policy engine is rule-based (optionally assisted by a Claude classifier) and can be evaded by careful
  phrasing; that is why individual subjects need human approval and repeated refusals escalate.
- Python cannot reliably erase secrets from memory; crypto-shredding covers stored data, not process memory or
  data already exported or downloaded.
- Data sent to third-party providers (Anthropic, Google Cloud Vision, TinEye, Brave) is subject to their terms and
  retention. Only sanitized previews and redacted excerpts are sent, and only when configured and permitted.
- Backups remain decryptable until their KEK epoch is destroyed (backup retention + one rotation period).
- Legal texts are templates and need review by counsel for each jurisdiction.
