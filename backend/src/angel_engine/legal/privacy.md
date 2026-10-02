---
title: Privacy Policy
version: 2026-10-01
effective: 2026-10-01
---
> **Template notice.** Adapt this policy to your organization (controller identity, legal bases,
> contact details, transfers) and have it reviewed by counsel or your data-protection officer.

## 1. Principles

Angel Engine is built for data minimization: it processes only what an investigation needs, redacts
sensitive personal data before storing anything, and deletes data on a schedule.

## 2. What we process

**About platform users:** account details (name, work email, role), authentication data (password hash,
encrypted authenticator secret), session records, attestations, and an audit trail of actions. IP
addresses are stored only as monthly-keyed pseudonyms whose keys are destroyed after 90 days.

**In investigations:** publicly available information collected by investigators, uploaded images and
the results of non-biometric analysis, notes, reports and AI-assistant interactions.

## 3. What we never process

- **Biometric identification.** Faces are detected only so they can be blurred; no face templates,
  embeddings or identities are ever created.
- **Sensitive data from sources.** Payment cards, bank accounts, government ID numbers, passwords and
  tokens, precise private addresses, personal phone numbers and personal email addresses are redacted
  *before* storage. Health information is flagged, hidden by default and excluded from AI processing.
- **Precise location.** GPS coordinates in image metadata are reduced to country or region level and the
  coordinates are discarded.

## 4. Security

Data is encrypted in transit (TLS) and at rest. Each investigation has its own encryption key; deleting
an investigation destroys that key, making remaining copies unreadable. Access is role-based and every
access is audited.

## 5. Retention (defaults; administrators may shorten them)

| Data | Default retention |
|---|---|
| Uploaded image originals | 24 hours after analysis |
| Sanitized previews and analysis results | Life of the investigation |
| Closed investigations | Archived after 90 days, deleted after 365 days (unless under legal hold) |
| AI-assistant transcripts | 30 days |
| Audit log | 2 years |
| Data exports | 24 hours |

## 6. Third-party processors

If enabled by your administrator, redacted evidence excerpts may be sent to the configured AI provider
(Anthropic) for analysis, and face-blurred image previews may be sent to configured reverse-image or
vision providers. Each provider's own retention terms apply to data it receives.

## 7. Your rights

You can review and revoke your sessions, export your personal data and request deletion of your
account from **Privacy & Data Controls**. People who believe they are the subject of an investigation
can use the public **Report abuse** form, including to request removal.
