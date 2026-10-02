# Angel Engine

**Angel Engine** is a lawful, privacy-first OSINT (open-source intelligence) investigation platform.
It helps authorized investigators collect, organize, analyze and verify **publicly available**
information — and it is deliberately *not* a people-search or facial-recognition service.

> *Investigate public evidence, verify sources, protect privacy, and never turn an AI inference into
> an identity claim.*

## What it does

- **Image investigation using non-biometric evidence only** — file and metadata analysis (with GPS
  generalized to region level), OCR of visible text with sensitive-data redaction, perceptual hashing
  and duplicate detection, object detection, clues such as domains, usernames, signs and landmarks.
  Faces are only *detected* so they can be blurred:
  *"A face was detected in the image. Angel Engine does not perform facial identification."*
- **Federated public-source research** through official APIs and robots-permitted public pages
  (web archives, domain registration data, certificate transparency, news, company registries,
  government publications, public profiles, forums, image sources, search APIs).
- **Evidence management** — every result is shown as
  **Source → Finding → Evidence → Timestamp → Confidence → Verification Status**, with immutable
  provenance (observed, source-reported, analyst inference, AI hypothesis) and audited, human-only
  status changes.
- **Evidence graph and timeline** in which every relationship carries its supporting sources.
- **Source-grounded AI assistant** (Claude) whose statements are tied to cited evidence; when evidence
  is insufficient it answers *"Insufficient public evidence to establish this conclusion."*
- **Cited reports** (HTML, Markdown, JSON, PDF) in which every factual claim links to its source.

## Safety and privacy by design

Lawful-purpose attestation, supervisor approval for investigations about individuals, an
acceptable-use policy engine that refuses doxxing, stalking, tracking and face-identification
requests (and suggests lawful alternatives), redaction of sensitive data before storage,
per-investigation encryption keys with crypto-shredding, a hash-chained audit log, retention
controls and deletion. See `docs/` for the architecture, security model and responsible-use notes.

## Repository layout

```
backend/    FastAPI API, background worker, image pipeline, connectors, AI layer (Python)
frontend/   Next.js web application (TypeScript)
deploy/     Docker Compose, Caddy, container images
docs/       Architecture, security, privacy, API and operations documentation
scripts/    Development helpers (local PostgreSQL/Redis, data builders, demo seed)
```

## Local development

Requirements: Python ≥ 3.11, Node.js 22 + pnpm, PostgreSQL 16, Redis, Tesseract OCR.

```bash
make setup          # backend virtualenv + dependencies
make services       # start local PostgreSQL (port 54329) and Redis (port 63799)
make migrate        # apply database migrations
make test           # backend test suite
```

See `make help` for all targets. Status: under active development.
