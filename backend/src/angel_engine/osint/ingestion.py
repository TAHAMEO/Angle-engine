"""Ingestion: connector records → sources, evidence, findings, entities, relationships, facts, timeline.

Everything passes through the evidence service (redaction → encryption → blind index). Each record
becomes one source-reported evidence item and one *unverified* finding that restates it; entities,
relationships, facts and dated events are attached to that evidence. Search-engine leads are returned
to the caller instead of being stored, and manual-review references become sources without evidence.
"""

from __future__ import annotations

import uuid
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import date
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from angel_engine.core.ids import new_id
from angel_engine.core.problems import ValidationProblem
from angel_engine.crypto.envelope import FieldCipher
from angel_engine.db.models import Entity, Fact, Investigation
from angel_engine.entities.service import EntityInput, add_mention, canonicalize, upsert_entity
from angel_engine.evidence.service import EvidenceInput, SourceInput, add_evidence, upsert_source
from angel_engine.evidence.urls import UrlError
from angel_engine.findings.service import FindingInput, LinkInput, create_finding
from angel_engine.graph.service import RelationshipInput, upsert_relationship
from angel_engine.guard import SourceKind
from angel_engine.osint import facts as fx
from angel_engine.osint.connectors.base import parse_date
from angel_engine.osint.suggestions import compare_facts, detect_syndication
from angel_engine.osint.types import ManualReference, NormalizedRecord, SourceCategory
from angel_engine.timeline.service import KINDS, PRECISIONS, EventInput, create_event, find_event

log = structlog.get_logger(__name__)

SOURCE_KINDS = {
    SourceCategory.PUBLIC_COMPANY_INFORMATION: SourceKind.REGISTRY,
    SourceCategory.PUBLIC_DIRECTORIES: SourceKind.REGISTRY,
    SourceCategory.PUBLIC_GOVERNMENT_INFORMATION: SourceKind.GOVERNMENT,
}
PUBLICATION_CATEGORIES = {
    SourceCategory.NEWS_ARTICLES,
    SourceCategory.PUBLIC_GOVERNMENT_INFORMATION,
    SourceCategory.PUBLIC_DOCUMENTS,
}
_ENTITY_ATTRIBUTE_KEYS = {"location_level", "country", "public_role_basis"}


@dataclass
class IngestStats:
    sources_created: int = 0
    evidence_created: int = 0
    duplicates: int = 0
    findings_created: int = 0
    entities_created: int = 0
    relationships_created: int = 0
    facts_created: int = 0
    events_created: int = 0
    references: int = 0
    suggestions: int = 0
    redactions: Counter[str] = field(default_factory=Counter)
    warnings: list[str] = field(default_factory=list)
    evidence_ids: list[uuid.UUID] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "sources_created": self.sources_created, "evidence_created": self.evidence_created,
            "duplicates": self.duplicates, "findings_created": self.findings_created,
            "entities_created": self.entities_created, "relationships_created": self.relationships_created,
            "facts_created": self.facts_created, "events_created": self.events_created,
            "references": self.references, "suggestions": self.suggestions, "redactions": dict(self.redactions),
        }  # fmt: skip


async def _organization_aliases(db: AsyncSession, inv: Investigation) -> dict[str, uuid.UUID]:
    rows = (
        await db.execute(
            select(Entity).where(
                Entity.investigation_id == inv.id, Entity.type == "organization", Entity.merged_into_id.is_(None)
            )
        )
    ).scalars()
    aliases: dict[str, uuid.UUID] = {}
    for entity in rows:
        if entity.name:
            aliases[entity.name.casefold()] = entity.id
            aliases[canonicalize("organization", entity.name)] = entity.id
    return {k: v for k, v in aliases.items() if len(k) >= 4}


def _iso_date(value: Any) -> date | None:
    parsed = parse_date(value)
    return parsed.date() if parsed else None


async def _add_fact(
    db: AsyncSession,
    cipher: FieldCipher,
    inv: Investigation,
    entity_id: uuid.UUID | None,
    attribute: str,
    value: Any,
    precision: str | None,
    evidence_id: uuid.UUID,
    valid_from: Any = None,
    valid_to: Any = None,
) -> uuid.UUID:
    fid = new_id()
    db.add(
        Fact(
            id=fid,
            investigation_id=inv.id,
            entity_id=entity_id,
            attribute=attribute,
            value=cipher.seal_json(value, table="facts", column="value", row_id=fid),
            value_type=type(value).__name__,
            precision=precision,
            valid_from=_iso_date(valid_from),
            valid_to=_iso_date(valid_to),
            evidence_id=evidence_id,
            provenance="source_reported",
        )
    )
    await db.flush()
    return fid


async def ingest_record(
    db: AsyncSession,
    cipher: FieldCipher,
    inv: Investigation,
    record: NormalizedRecord,
    *,
    run_id: uuid.UUID | None,
    actor_id: uuid.UUID | None,
    stats: IngestStats,
    new_fact_ids: list[uuid.UUID],
) -> None:
    kind = SOURCE_KINDS.get(record.category, SourceKind.WEB)
    try:
        source = await upsert_source(
            db,
            cipher,
            inv,
            SourceInput(
                url=record.final_url or record.url,
                category=record.category.value,
                connector_id=record.connector_id,
                title=record.title,
                publisher=record.publisher,
                published_at=record.published_at,
                access_status=record.access_status.value,
                archived_url=record.archived_url,
                created_by=actor_id,
                source_kind=kind,
            ),
        )
    except UrlError as exc:
        stats.warnings.append(f"Skipped a record with an unusable URL ({exc}).")
        return
    stats.sources_created += int(source.created)
    stats.redactions.update(source.redaction_counts)
    metadata = {k: v for k, v in record.metadata.items() if k != "events"}
    added = await add_evidence(
        db,
        cipher,
        inv,
        EvidenceInput(
            excerpt=record.excerpt,
            evidence_type=record.evidence_type.value,
            provenance="source_reported",
            source_id=source.source.id,
            collection_run_id=run_id,
            captured_at=record.retrieved_at,
            published_at=record.published_at,
            extra=metadata or None,
            source_kind=kind,
            organization_context=record.organization_context,
            created_by=actor_id,
        ),
    )
    stats.redactions.update(added.item.redaction_counts if added.created else {})
    if not added.created:
        stats.duplicates += 1
        return
    evidence = added.item
    stats.evidence_created += 1
    stats.evidence_ids.append(evidence.id)
    finding = await create_finding(
        db,
        cipher,
        inv,
        FindingInput(
            statement=record.statement,
            category=record.category.value,
            provenance="source_reported",
            links=(LinkInput(evidence.id, directly_states=True),),
            created_via="connector",
            created_by=actor_id,
            source_kind=kind,
            event_time=record.published_at,
            event_precision="day" if record.published_at else None,
        ),
    )
    stats.findings_created += 1

    entities: dict[tuple[str, str], Entity] = {}
    for draft in record.entities:
        attrs = {k: str(v) for k, v in draft.attributes.items() if k not in _ENTITY_ATTRIBUTE_KEYS and v is not None}
        try:
            entity, created = await upsert_entity(
                db,
                cipher,
                inv,
                EntityInput(
                    type=draft.type,
                    name=draft.name,
                    attributes=attrs,
                    location_level=draft.attributes.get("location_level"),
                    country=draft.attributes.get("country"),
                    public_role_basis=draft.attributes.get("public_role_basis"),
                    created_via="connector",
                ),
            )
        except ValidationProblem as exc:
            stats.warnings.append(f"An entity was not recorded: {exc.detail}")
            continue
        stats.entities_created += int(created)
        entities[(draft.type, draft.canonical)] = entity
        await add_mention(db, inv, entity.id, evidence.id)

    for rel in record.relationships:
        source_entity = entities.get((rel.from_type, rel.from_canonical))
        target_entity = entities.get((rel.to_type, rel.to_canonical))
        if source_entity is None or target_entity is None or source_entity.id == target_entity.id:
            continue
        try:
            _, created = await upsert_relationship(
                db,
                inv,
                RelationshipInput(
                    from_entity_id=source_entity.id,
                    rel_type=rel.rel_type,
                    to_entity_id=target_entity.id,
                    evidence_ids=(evidence.id,),
                    provenance="source_reported",
                    created_via="connector",
                    created_by=actor_id,
                ),
            )
        except ValidationProblem as exc:
            stats.warnings.append(f"A relationship was not recorded: {exc.detail}")
            continue
        stats.relationships_created += int(created)

    for draft_fact in record.facts:
        fact_entity = entities.get((draft_fact.entity_type, draft_fact.entity_canonical))
        new_fact_ids.append(
            await _add_fact(
                db,
                cipher,
                inv,
                fact_entity.id if fact_entity else None,
                draft_fact.attribute,
                draft_fact.value,
                draft_fact.precision,
                evidence.id,
                draft_fact.valid_from,
                draft_fact.valid_to,
            )
        )
        stats.facts_created += 1
    # Founding years stated in text about organizations already known to the investigation.
    if not record.facts:
        aliases = await _organization_aliases(db, inv)
        for entity_id, year in fx.founding_years(record.excerpt, {k: str(v) for k, v in aliases.items()}):
            new_fact_ids.append(
                await _add_fact(db, cipher, inv, uuid.UUID(entity_id), "org.inception", year, "year", evidence.id)
            )
            stats.facts_created += 1

    events = list(record.metadata.get("events") or [])
    if not events and record.published_at and record.category in PUBLICATION_CATEGORIES:
        events.append(
            {
                "kind": "publication",
                "date": record.published_at.isoformat(),
                "precision": "day",
                "title": f"Published: {record.title[:140]}",
            }
        )
    for event in events:
        when = parse_date(event.get("date"))
        if when is None or event.get("kind") not in KINDS or event.get("precision", "day") not in PRECISIONS:
            continue
        if await find_event(db, inv, event["kind"], when, evidence.id) is not None:
            continue
        await create_event(
            db,
            cipher,
            inv,
            EventInput(
                occurred_start=when,
                precision=event.get("precision", "day"),
                kind=event["kind"],
                title=str(event.get("title") or record.title)[:300],
                evidence_ids=(evidence.id,),
                finding_id=finding.id,
                provenance="source_reported",
                created_via="connector",
                created_by=actor_id,
            ),
        )
        stats.events_created += 1


async def ingest_reference(
    db: AsyncSession,
    cipher: FieldCipher,
    inv: Investigation,
    reference: ManualReference,
    *,
    connector_id: str,
    category: SourceCategory,
    actor_id: uuid.UUID | None,
    stats: IngestStats,
) -> None:
    try:
        upsert = await upsert_source(
            db,
            cipher,
            inv,
            SourceInput(
                url=reference.url,
                category=category.value,
                connector_id=connector_id,
                title=reference.note,
                access_status=reference.reason.value,
                created_by=actor_id,
            ),
        )
    except UrlError:
        return
    stats.references += 1
    stats.sources_created += int(upsert.created)


async def ingest(
    db: AsyncSession,
    cipher: FieldCipher,
    inv: Investigation,
    *,
    connector_id: str,
    category: SourceCategory,
    records: Sequence[NormalizedRecord],
    references: Sequence[ManualReference] = (),
    run_id: uuid.UUID | None = None,
    actor_id: uuid.UUID | None = None,
) -> tuple[IngestStats, list[NormalizedRecord]]:
    """Persist ``records`` (except leads, which are returned) and ``references``; then run suggestions."""
    stats = IngestStats()
    leads: list[NormalizedRecord] = []
    new_fact_ids: list[uuid.UUID] = []
    for record in records:
        if record.is_lead:
            leads.append(record)
            continue
        async with db.begin_nested():
            await ingest_record(
                db, cipher, inv, record, run_id=run_id, actor_id=actor_id, stats=stats, new_fact_ids=new_fact_ids
            )
    for reference in references:
        await ingest_reference(
            db, cipher, inv, reference, connector_id=connector_id, category=category, actor_id=actor_id, stats=stats
        )
    stats.suggestions += await detect_syndication(db, cipher, inv, stats.evidence_ids)
    counts = await compare_facts(db, cipher, inv, new_fact_ids)
    stats.suggestions += counts["contradictions"] + counts["corroborations"]
    return stats, leads
