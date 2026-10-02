"""Registries and public directories: RDAP, certificate transparency (crt.sh), GLEIF, SEC EDGAR, Wikidata.

Personal data is dropped at the source: RDAP contacts other than organizations are ignored, GLEIF
addresses are kept at city/country level, SEC insider forms (3/4/5) are references only, and Wikidata
records about people keep only public-role properties.
"""

from __future__ import annotations

from typing import Any, ClassVar

from angel_engine.osint.connectors.base import Connector, ConnectorContext, ConnectorError, clip, parse_date
from angel_engine.osint.types import (
    AccessStatus,
    ConnectorInfo,
    ConnectorQuery,
    ConnectorResult,
    EntityDraft,
    EvidenceType,
    FactDraft,
    InputType,
    ManualReference,
    NormalizedRecord,
    RelationshipDraft,
    SourceCategory,
)

PD = SourceCategory.PUBLIC_DIRECTORIES
CO = SourceCategory.PUBLIC_COMPANY_INFORMATION


def _domain(value: str) -> str:
    value = value.strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0]
    return value.removeprefix("www.")


# --------------------------------------------------------------------------------------------------
# RDAP
# --------------------------------------------------------------------------------------------------
def _vcard_fields(entity: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    vcard = entity.get("vcardArray")
    if isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list):
        for item in vcard[1]:
            if isinstance(item, list) and len(item) >= 4 and isinstance(item[3], str):
                out.setdefault(str(item[0]).lower(), item[3])
    return out


class Rdap(Connector):
    info: ClassVar[ConnectorInfo] = ConnectorInfo(
        id="rdap",
        name="RDAP domain registration data",
        category=PD,
        description="Registrar, registration and expiry dates, status and name servers for a domain (personal "
        "contacts are dropped).",
        input_types=(InputType.DOMAIN,),
        docs_url="https://www.rfc-editor.org/rfc/rfc9083",
        terms_note="Uses the IANA RDAP bootstrap registry; registrant privacy redactions are respected.",
        allowed_in_restricted_mode=True,
        min_interval_s=1.0,
    )

    async def _base_url(self, ctx: ConnectorContext, tld: str) -> str:
        bootstrap = await self.get_json(ctx, "https://data.iana.org/rdap/dns.json") or {}
        for tlds, urls in bootstrap.get("services", []):
            if tld in tlds and urls:
                return str(urls[0]).rstrip("/") + "/"
        return "https://rdap.org/"

    async def search(self, query: ConnectorQuery, ctx: ConnectorContext) -> ConnectorResult:
        domain = _domain(query.value)
        base = await self._base_url(ctx, domain.rsplit(".", 1)[-1])
        data = await self.get_json(ctx, f"{base}domain/{domain}")
        if not data:
            return ConnectorResult(warnings=(f"No RDAP record was found for {domain}.",))
        events = {e.get("eventAction"): parse_date(e.get("eventDate")) for e in data.get("events", [])}
        registered, expires = events.get("registration"), events.get("expiration")
        nameservers = sorted(
            {str(ns.get("ldhName", "")).lower() for ns in data.get("nameservers", []) if ns.get("ldhName")}
        )
        registrar = registrant_org = None
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            fields = _vcard_fields(entity)
            if "registrar" in roles:
                registrar = fields.get("fn") or fields.get("org")
            if "registrant" in roles and not ctx.restricted_mode:
                org = fields.get("org")
                kind = fields.get("kind", "")
                if org and "redacted" not in org.lower() and kind in ("org", ""):
                    registrant_org = org  # organizations only; individuals' contact data is never kept
        parts = [f"RDAP record for {domain}."]
        if registrar:
            parts.append(f"Registrar: {registrar}.")
        if registered:
            parts.append(f"Registered: {registered.date().isoformat()}.")
        if expires:
            parts.append(f"Expires: {expires.date().isoformat()}.")
        if data.get("status"):
            parts.append("Status: " + ", ".join(map(str, data["status"][:6])) + ".")
        if nameservers:
            parts.append("Name servers: " + ", ".join(nameservers[:8]) + ".")
        if registrant_org:
            parts.append(f"Registrant organization: {registrant_org}.")
        entities = [EntityDraft("domain", domain, domain)]
        relationships = []
        if registrar:
            entities.append(EntityDraft("organization", registrar, registrar))
        if registrant_org:
            entities.append(EntityDraft("organization", registrant_org, registrant_org))
            relationships.append(RelationshipDraft(domain, "domain", "registered_by", registrant_org, "organization"))
        facts = []
        if registered:
            facts.append(
                FactDraft(domain, "domain", "domain.registration_date", registered.date().isoformat(), precision="day")
            )
        events_meta = (
            [
                {
                    "kind": "registration",
                    "date": registered.isoformat(),
                    "precision": "day",
                    "title": f"Domain {domain} registered",
                }
            ]
            if registered
            else []
        )
        record = NormalizedRecord(
            connector_id=self.info.id,
            category=PD,
            url=f"{base}domain/{domain}",
            title=f"RDAP: {domain}",
            excerpt=" ".join(parts),
            statement=f"The RDAP registry record for {domain} lists "
            + (f"a registration date of {registered.date().isoformat()}" if registered else "its registration data")
            + (f" and the registrar {registrar}" if registrar else "")
            + ".",
            evidence_type=EvidenceType.REGISTRY_RECORD,
            published_at=events.get("last changed"),
            publisher="RDAP registry",
            entities=tuple(entities),
            facts=tuple(facts),
            relationships=tuple(relationships),
            organization_context=True,
            metadata={"events": events_meta, "nameservers": nameservers},
        )
        return ConnectorResult(records=(record,))


# --------------------------------------------------------------------------------------------------
# Certificate transparency
# --------------------------------------------------------------------------------------------------
class CrtSh(Connector):
    info: ClassVar[ConnectorInfo] = ConnectorInfo(
        id="crtsh",
        name="Certificate transparency (crt.sh)",
        category=PD,
        description="Unexpired TLS certificates logged for a domain; the names they list are recorded as "
        "references and never probed.",
        input_types=(InputType.DOMAIN,),
        docs_url="https://crt.sh/",
        terms_note="Single attempt per request; crt.sh is a free community service.",
        allowed_in_restricted_mode=True,
        min_interval_s=5.0,
    )

    async def search(self, query: ConnectorQuery, ctx: ConnectorContext) -> ConnectorResult:
        domain = _domain(query.value)
        rows = (
            await self.get_json(
                ctx, "https://crt.sh/", params={"q": f"%.{domain}", "output": "json", "exclude": "expired"}
            )
            or []
        )
        if not rows:
            return ConnectorResult(warnings=(f"No unexpired certificates are logged for {domain}.",))
        names = sorted(
            {
                n.strip().lower()
                for row in rows
                for n in str(row.get("name_value", "")).splitlines()
                if n.strip() and not n.startswith("*")
            }
        )[:50]
        issued = sorted(d for d in (parse_date(r.get("not_before")) for r in rows) if d is not None)
        issuers = sorted({str(r.get("issuer_name", "")).split("O=")[-1].split(",")[0] for r in rows})[:5]
        first = issued[0] if issued else None
        record = NormalizedRecord(
            connector_id=self.info.id,
            category=PD,
            url=f"https://crt.sh/?q=%25.{domain}",
            title=f"Certificates for {domain}",
            excerpt=f"{len(rows)} unexpired certificate(s) for {domain} are logged in certificate-transparency logs"
            + (f"; the earliest valid from {first.date().isoformat()}" if first else "")
            + f". Names listed: {', '.join(names)}. Issuers: {', '.join(i for i in issuers if i)}.",
            statement=f"Certificate-transparency logs list {len(names)} host name(s) under {domain}.",
            evidence_type=EvidenceType.REGISTRY_RECORD,
            published_at=first,
            publisher="crt.sh",
            entities=(EntityDraft("domain", domain, domain),),
            organization_context=True,
            metadata={"names": names},
        )
        return ConnectorResult(records=(record,))


# --------------------------------------------------------------------------------------------------
# GLEIF
# --------------------------------------------------------------------------------------------------
class Gleif(Connector):
    info: ClassVar[ConnectorInfo] = ConnectorInfo(
        id="gleif",
        name="GLEIF legal entity identifiers",
        category=CO,
        description="Legal name, jurisdiction, legal-entity creation date and LEI registration for companies.",
        input_types=(InputType.ORGANIZATION, InputType.KEYWORD),
        docs_url="https://www.gleif.org/en/lei-data/gleif-api",
        terms_note="GLEIF data is CC0. Addresses are kept at city and country level only.",
        allowed_in_restricted_mode=True,
        min_interval_s=1.0,
    )

    async def search(self, query: ConnectorQuery, ctx: ConnectorContext) -> ConnectorResult:
        data = (
            await self.get_json(
                ctx,
                "https://api.gleif.org/api/v1/lei-records",
                params={"filter[entity.legalName]": query.value.strip(), "page[size]": min(query.limit, 10)},
            )
            or {}
        )
        records = []
        for item in data.get("data", [])[: query.limit]:
            attrs = item.get("attributes", {})
            entity, registration = attrs.get("entity", {}), attrs.get("registration", {})
            name = (entity.get("legalName") or {}).get("name") or query.value
            address = entity.get("legalAddress") or {}
            city, country = address.get("city"), address.get("country")
            created = parse_date(entity.get("creationDate"))
            initial = parse_date(registration.get("initialRegistrationDate"))
            lei = attrs.get("lei") or item.get("id")
            excerpt = (
                f"{name} (LEI {lei}) — status {entity.get('status', 'unknown')}, jurisdiction "
                f"{entity.get('jurisdiction', 'unknown')}, legal address in {city or '?'}, {country or '?'}."
                + (f" Legal entity created {created.date().isoformat()}." if created else "")
                + (f" LEI first registered {initial.date().isoformat()}." if initial else "")
            )
            facts = []
            if created:
                facts.append(
                    FactDraft(
                        name, "organization", "org.legal_creation_date", created.date().isoformat(), precision="day"
                    )
                )
            if initial:
                facts.append(
                    FactDraft(
                        name, "organization", "org.lei_registration_date", initial.date().isoformat(), precision="day"
                    )
                )
            entities = [EntityDraft("organization", name, name, {"lei": lei})]
            relationships = []
            if city and country:
                entities.append(
                    EntityDraft(
                        "location",
                        city,
                        f"locality:{country}:{city}",
                        {"location_level": "locality", "country": country},
                    )
                )
                relationships.append(
                    RelationshipDraft(name, "organization", "located_in", f"locality:{country}:{city}", "location")
                )
            records.append(
                NormalizedRecord(
                    connector_id=self.info.id,
                    category=CO,
                    url=f"https://search.gleif.org/#/record/{lei}",
                    title=f"GLEIF: {name}",
                    excerpt=excerpt,
                    statement=f"GLEIF lists {name} with legal-entity creation date "
                    f"{created.date().isoformat() if created else 'not stated'}.",
                    evidence_type=EvidenceType.REGISTRY_RECORD,
                    published_at=parse_date(registration.get("lastUpdateDate")),
                    publisher="GLEIF",
                    entities=tuple(entities),
                    facts=tuple(facts),
                    relationships=tuple(relationships),
                    organization_context=True,
                    metadata={
                        "lei": lei,
                        "events": [
                            {
                                "kind": "corporate_event",
                                "date": created.isoformat(),
                                "precision": "day",
                                "title": f"{name} created as a legal entity",
                            }
                        ]
                        if created
                        else [],
                    },
                )
            )
        return ConnectorResult(
            records=tuple(records), warnings=() if records else ("No LEI record matches this exact legal name.",)
        )


# --------------------------------------------------------------------------------------------------
# SEC EDGAR
# --------------------------------------------------------------------------------------------------
INSIDER_FORMS = frozenset({"3", "4", "5", "3/A", "4/A", "5/A"})


class SecEdgar(Connector):
    info: ClassVar[ConnectorInfo] = ConnectorInfo(
        id="sec_edgar",
        name="SEC EDGAR filings",
        category=CO,
        description="Company filings index from the U.S. SEC (insider forms 3/4/5 are references only).",
        input_types=(InputType.ORGANIZATION, InputType.KEYWORD),
        docs_url="https://www.sec.gov/search-filings/edgar-application-programming-interfaces",
        terms_note="SEC fair-access policy: declared User-Agent with a contact address, ≤ 10 requests/second.",
        requires_key="operator_contact",
        allowed_in_restricted_mode=True,
        min_interval_s=0.2,
    )

    def status(self, settings: Any) -> tuple[str, str | None]:
        state, reason = super().status(settings)
        if state == "needs_key":
            return state, "Set ANGEL_OPERATOR_CONTACT (an address the SEC can contact) to enable EDGAR."
        return state, reason

    async def search(self, query: ConnectorQuery, ctx: ConnectorContext) -> ConnectorResult:
        contact = ctx.settings.operator_contact
        if not contact:
            raise ConnectorError("not_configured", "operator contact missing")
        headers = {"User-Agent": f"{ctx.http.user_agent} {contact}"}
        hits = (
            await self.get_json(
                ctx,
                "https://efts.sec.gov/LATEST/search-index",
                params={"q": f'"{query.value.strip()}"'},
                headers=headers,
            )
            or {}
        )
        records: list[NormalizedRecord] = []
        references: list[ManualReference] = []
        for hit in (hits.get("hits", {}) or {}).get("hits", [])[: query.limit]:
            src = hit.get("_source", {})
            form = str(src.get("form", ""))
            names = src.get("display_names") or []
            adsh = str(src.get("adsh", ""))
            cik = (src.get("ciks") or [""])[0]
            url = (
                f"https://www.sec.gov/Archives/edgar/data/{int(cik) if str(cik).isdigit() else cik}/"
                f"{adsh.replace('-', '')}/"
                if adsh
                else "https://www.sec.gov/edgar/search/"
            )
            if form in INSIDER_FORMS:
                references.append(
                    ManualReference(
                        url, AccessStatus.REFERENCE_ONLY, f"SEC Form {form} (insider transaction) — reference only."
                    )
                )
                continue
            filed = parse_date(src.get("file_date"))
            company = names[0].split(" (CIK")[0] if names else query.value
            records.append(
                NormalizedRecord(
                    connector_id=self.info.id,
                    category=CO,
                    url=url,
                    title=f"SEC {form}: {company}",
                    excerpt=f"{company} filed Form {form} with the SEC on {filed.date().isoformat() if filed else '?'} "
                    f"(accession {adsh}).",
                    statement=f"{company} filed a Form {form} with the U.S. SEC"
                    + (f" on {filed.date().isoformat()}." if filed else "."),
                    evidence_type=EvidenceType.REGISTRY_RECORD,
                    published_at=filed,
                    publisher="U.S. SEC",
                    entities=(EntityDraft("organization", company, company),),
                    organization_context=True,
                    metadata={"form": form, "accession": adsh},
                )
            )
        return ConnectorResult(records=tuple(records), references=tuple(references))


# --------------------------------------------------------------------------------------------------
# Wikidata
# --------------------------------------------------------------------------------------------------
HUMAN = "Q5"
PERSON_SAFE_PROPERTIES = ("P106", "P39", "P108", "P463", "P856")  # occupation, position, employer, member, website
PRECISION = {9: "year", 10: "month", 11: "day"}


def _claim_values(entity: dict[str, Any], prop: str) -> list[Any]:
    out = []
    for claim in entity.get("claims", {}).get(prop, []):
        value = (claim.get("mainsnak", {}).get("datavalue") or {}).get("value")
        if value is not None:
            out.append(value)
    return out


class Wikidata(Connector):
    info: ClassVar[ConnectorInfo] = ConnectorInfo(
        id="wikidata",
        name="Wikidata",
        category=PD,
        description="Structured facts about organizations and public entities (inception, official website, "
        "country). Records about people keep only public-role properties.",
        input_types=(InputType.ORGANIZATION, InputType.KEYWORD),
        docs_url="https://www.wikidata.org/wiki/Wikidata:Data_access",
        terms_note="CC0 data. Requests identify the bot as required by the Wikimedia User-Agent policy.",
        allowed_in_restricted_mode=False,
        min_interval_s=1.0,
    )

    async def search(self, query: ConnectorQuery, ctx: ConnectorContext) -> ConnectorResult:
        found = (
            await self.get_json(
                ctx,
                "https://www.wikidata.org/w/api.php",
                params={
                    "action": "wbsearchentities",
                    "search": query.value.strip(),
                    "language": "en",
                    "format": "json",
                    "type": "item",
                    "limit": min(query.limit, 5),
                },
            )
            or {}
        )
        records = []
        for hit in found.get("search", [])[:3]:
            qid = hit.get("id")
            data = await self.get_json(ctx, f"https://www.wikidata.org/wiki/Special:EntityData/{qid}.json") or {}
            entity = data.get("entities", {}).get(qid, {})
            label = (entity.get("labels", {}).get("en") or {}).get("value") or hit.get("label") or qid
            description = (entity.get("descriptions", {}).get("en") or {}).get("value") or ""
            is_human = any(v.get("id") == HUMAN for v in _claim_values(entity, "P31") if isinstance(v, dict))
            facts, entities, relationships, parts = [], [], [], [f"{label}: {description}." if description else label]
            websites = [v for v in _claim_values(entity, "P856") if isinstance(v, str)]
            if is_human:
                # Only public-role information is kept for people; no birth data, family, residence or photos.
                entities.append(
                    EntityDraft(
                        "public_figure",
                        label,
                        label,
                        {"public_role_basis": f"Wikidata: {description}" if description else "Wikidata item"},
                    )
                )
                if websites:
                    parts.append(f"Official website: {websites[0]}.")
            else:
                entities.append(EntityDraft("organization", label, label, {"wikidata": qid}))
                for value in _claim_values(entity, "P571")[:1]:
                    if isinstance(value, dict) and value.get("time"):
                        precision = PRECISION.get(int(value.get("precision", 9)), "year")
                        year = value["time"].lstrip("+")[:4]
                        iso = value["time"].lstrip("+")[:10].replace("-00", "-01")
                        facts.append(FactDraft(label, "organization", "org.inception", iso, precision=precision))
                        parts.append(f"Inception: {year if precision == 'year' else iso}.")
                for site in websites[:1]:
                    host = _domain(site)
                    parts.append(f"Official website: {site}.")
                    entities.append(EntityDraft("website", host, host))
                    relationships.append(RelationshipDraft(host, "website", "operated_by", label, "organization"))
            records.append(
                NormalizedRecord(
                    connector_id=self.info.id,
                    category=PD,
                    url=f"https://www.wikidata.org/wiki/{qid}",
                    title=f"Wikidata: {label}",
                    excerpt=clip(" ".join(parts), 1200),
                    statement=f"Wikidata describes {label}"
                    + (f" as “{clip(description, 120)}”." if description else "."),
                    evidence_type=EvidenceType.REGISTRY_RECORD,
                    publisher="Wikidata",
                    entities=tuple(entities),
                    facts=tuple(facts),
                    relationships=tuple(relationships),
                    organization_context=not is_human,
                    metadata={"qid": qid, "human": is_human},
                )
            )
        return ConnectorResult(
            records=tuple(records), warnings=() if records else ("No Wikidata item matches this name.",)
        )
