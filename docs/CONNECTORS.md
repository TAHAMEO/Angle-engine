# Connectors

A connector turns one lawful, policy-screened query into records from **one** public source, using that source's
official API or pages that allow automated access. Connectors live in
`backend/src/angel_engine/osint/connectors/` and are registered in `osint/registry.py`.

## Rules every connector follows

- **Official interfaces only.** Documented APIs, or public pages whose `robots.txt` allows `AngelEngineBot`. No
  scraping of search engines, no logins, cookies, CAPTCHA solving, paywall bypassing, private or leaked data,
  people-search or breach databases.
- **Walls become references.** A page behind a login, paywall, CAPTCHA, SSO redirect or a robots disallow is
  recorded as a *manual-review reference* (access status `login_required`, `paywalled`, `robots_disallowed` or
  `reference_only`) and is never fetched or bypassed.
- **Guarded network access.** All traffic goes through `SafeHttpClient` in the egress worker: DNS resolved once and
  pinned, only globally routable addresses, redirects re-validated, ports 80/443, no cookies/credentials/Referer,
  byte caps, per-domain rate limits (each connector's minimum interval plus `Crawl-delay`), `Retry-After` honoured.
- **Honest identification.** `User-Agent: AngelEngineBot/1.0 (+<ANGEL_BOT_INFO_URL>)` — point the URL at a page
  describing your deployment and how to contact you. SEC EDGAR additionally requires `ANGEL_OPERATOR_CONTACT`
  (an organizational contact address). No personal data of users is ever placed in requests.
- **robots.txt** (RFC 9309, Protego): fetched by us and cached for 24 hours per origin; 2xx is obeyed
  (`AngelEngineBot` group, else `*`), 4xx means no restrictions, 5xx or network errors mean "disallow everything"
  until the next check.
- **Parsing happens elsewhere.** Captured HTML and PDFs are parsed in a sandboxed child process on the analysis
  worker, which has no network access. Results are redacted before storage.
- **Provenance.** Connector results become sources, `source_reported` evidence and *unverified* findings. Nothing a
  connector returns is treated as confirmed until a person verifies it.
- **Restricted mode** (individual subjects) limits the catalogue (table below), and profile lookups by username
  need a written purpose note and a supervisor's approval of the run.

## Catalogue

| Id | Source | Category | Inputs | Key | Restricted mode | Notes |
|---|---|---|---|---|---|---|
| `web_capture` | Web page capture | Websites | URL | — | yes | robots.txt, honest UA; captures limited to public pages, copyright stays with the publisher |
| `wayback` | Internet Archive Wayback Machine | Websites | URL, domain | — | yes | Read-only CDX queries; Save Page Now is never used |
| `common_crawl` | Common Crawl index | Websites | URL | — | yes | Index metadata only; WARC payloads are not downloaded |
| `dns` | DNS records | Websites | domain | — | yes | Single lookups through a public resolver; no zone transfers or enumeration |
| `wikipedia` | Wikipedia | Websites | keyword, organization | — | no | CC BY-SA; summaries quoted with attribution and revision |
| `gdelt` | GDELT DOC 2.0 news index | News articles | keyword, organization, domain | — | yes | ≥ 10 s between requests; articles captured only on request |
| `mastodon` | Mastodon public profiles | Public social media | username | — | approval | Honours `discoverable`/`indexable: false`; purpose note required |
| `bluesky` | Bluesky public profiles | Public social media | username | — | approval | Honours the `!no-unauthenticated` label; purpose note required |
| `github` | GitHub public profiles | Public profiles | username, organization | optional `ANGEL_GITHUB_TOKEN` | approval | Public profile fields only; e-mail reduced to its domain |
| `internet_archive` | Internet Archive collections | Public documents | keyword, organization | — | yes | Metadata only |
| `gleif` | GLEIF legal entity identifiers | Public company information | organization, keyword | — | yes | CC0; addresses kept at city/country level |
| `sec_edgar` | SEC EDGAR filings | Public company information | organization, keyword | `ANGEL_OPERATOR_CONTACT` | yes | Fair-access policy (declared UA, ≤ 10 req/s); insider forms are references only |
| `gov_uk` | GOV.UK search | Public government information | keyword, organization | — | yes | Open Government Licence v3.0 |
| `federal_register` | U.S. Federal Register | Public government information | keyword, organization | — | yes | Public domain |
| `rdap` | RDAP registration data | Public directories | domain | — | yes | IANA bootstrap; registrant contacts dropped, privacy redactions respected |
| `crtsh` | Certificate transparency (crt.sh) | Public directories | domain | — | yes | One attempt, ≥ 5 s apart; host names are references, never probed |
| `wikidata` | Wikidata | Public directories | organization, keyword | — | no | For people only label, description, occupation, positions, employer, memberships and website |
| `nominatim` | OpenStreetMap Nominatim | Public directories | place | — | no | Broad, user-typed places only; ≤ 1 req/s; never used to resolve addresses of people |
| `hacker_news` | Hacker News (Algolia) | Public forums | keyword, organization, domain | — | no | Public posts only |
| `stack_exchange` | Stack Exchange | Public forums | keyword, organization | optional `ANGEL_STACKEXCHANGE_KEY` | no | CC BY-SA; API back-off honoured |
| `wikimedia_commons` | Wikimedia Commons | Public image sources | keyword | — | no | Licence from each file's metadata |
| `openverse` | Openverse | Public image sources | keyword | — | no | Anonymous limits (≤ 20 results/page, 1 req/s) |
| `tineye` | TinEye | Public image sources | image | `ANGEL_TINEYE_API_KEY` | no | Sanitized preview only; face/person gate |
| `google_vision` | Google Cloud Vision | Public image sources | image | `ANGEL_GOOGLE_VISION_API_KEY` | no | LOGO/LANDMARK/TEXT/WEB detection only, never FACE; web entities and best-guess labels discarded |
| `brave_search` | Brave Search API | Search-engine results | keyword, organization, domain | `ANGEL_BRAVE_API_KEY` | yes | Results are transient leads (below) |

*approval* = available in restricted mode only as a run that a supervisor approves.

The connector page in the application (Sources → Connectors, and Administration → Connectors) shows each
connector's status: **ready**, **needs key**, or **disabled** (`ANGEL_DISABLED_CONNECTORS='["gdelt","crtsh"]'`,
a JSON list).

## Search-engine results

Brave Search results are **leads**, not evidence: they are kept encrypted on the collection run for 24 hours so the
investigator can choose which pages to capture, then discarded. Only the pages a person selects are captured (with
the web-capture rules above) and stored. Check that your Brave plan permits the storage you need.

Angel Engine deliberately has no Google Custom Search (closed to new customers, ending 2027-01-01), Bing Search
APIs (retired in August 2025) or scraping-based SERP services. Instead, **manual search links** (Collect public sources →
*Search it yourself*) build Google, Bing, DuckDuckGo, Brave, Google News and Wayback URLs that the investigator opens in
their own browser; the query is still policy-screened.

## Image providers

Public-occurrence search (TinEye, Google Cloud Vision) and Claude vision clues only ever receive the **sanitized
preview** — faces and sensitive text blurred, metadata stripped. If the image contains faces or people, a
supervisor other than the uploader must approve the search with a recorded purpose, and these searches are never
available in restricted mode. Matches are recorded as reports by the provider (`source_reported`), with match type
and crawl dates; landmark and logo labels from providers are AI-hypothesis clues.

## Offline fixture mode

With `ANGEL_CONNECTOR_MODE=fixtures` (development, tests and the demo only; refused in production), connectors talk
to a `FixtureTransport` that replays recorded responses from `backend/src/angel_engine/osint/fixtures/*.json`
instead of the network. The fixtures follow each source's documented format and use fictional `.example` data.

## Adding a connector

1. Subclass `Connector` (`osint/connectors/base.py`) and declare a `ConnectorInfo`: `id`, `name`, `category`
   (one of the 11 source categories), `input_types`, `docs_url`, `terms_note`, `requires_key`/`key_optional`,
   `person_oriented`, `allowed_in_restricted_mode`, `min_interval_s`.
2. Implement `search()` using only `ctx.http` (the `SafeHttpClient`). Return records and `ManualReference`s; raise
   `ConnectorError` with a safe code on failure. Do not parse untrusted HTML or PDFs in the connector — return a
   `RawCapture` for the analysis worker.
3. Drop personal fields you do not need at the connector boundary (contacts, street addresses, birth dates); the
   sensitive-data guard is a second line of defence, not the first.
4. Add a fixture under `osint/fixtures/` and tests in `tests/` covering normalisation, rate limits, error mapping
   and restricted-mode behaviour.
5. Register it in `osint/registry.py` and document it in the table above, including the source's terms.

Before enabling a connector in production, read the source's current terms of service and API policies; they
change, and the operator is responsible for complying with them.
