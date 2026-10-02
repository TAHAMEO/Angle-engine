"""Sources and evidence items: redact, normalize, de-duplicate, encrypt and index.

Every piece of collected or observed text passes through the sensitive-data guard here, *before* it
is encrypted, tokenized for search or stored. Evidence items are immutable once written (database
trigger); only reviewer annotations (credibility, broad location) can change later.
"""

from __future__ import annotations

import unicodedata
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from angel_engine.core.clock import utcnow
from angel_engine.core.ids import new_id
from angel_engine.core.problems import ValidationProblem
from angel_engine.crypto.blind_index import tokens
from angel_engine.crypto.envelope import FieldCipher
from angel_engine.crypto.keyed_hash import content_mac, url_mac
from angel_engine.db.models import EvidenceItem, Investigation, Source
from angel_engine.evidence.labels import next_label
from angel_engine.evidence.simhash import keyed_simhash
from angel_engine.evidence.urls import normalize_url
from angel_engine.guard import (
    RedactionContext,
    RedactionMode,
    RedactionResult,
    SourceKind,
    redact_mapping,
    redact_text,
)

MAX_EXCERPT_CHARS = 100_000
MAX_TITLE_CHARS = 500
EVIDENCE_PROVENANCES = ("observed", "source_reported")


def redaction_mode(inv: Investigation) -> RedactionMode:
    return RedactionMode.RESTRICTED if inv.restricted_mode else RedactionMode.STANDARD


def normalized_for_mac(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).casefold().split())


# --------------------------------------------------------------------------------------------------
# Sources
# --------------------------------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class SourceInput:
    url: str
    category: str
    connector_id: str
    title: str | None = None
    publisher: str | None = None
    published_at: datetime | None = None
    access_status: str = "captured"
    archived_url: str | None = None
    reliability: str | None = None
    ownership_group: str | None = None
    created_by: uuid.UUID | None = None
    source_kind: SourceKind = SourceKind.WEB


@dataclass(frozen=True, slots=True)
class SourceUpsert:
    source: Source
    created: bool
    redaction_counts: dict[str, int] = field(default_factory=dict)


async def _find_source(db: AsyncSession, inv_id: uuid.UUID, mac: bytes) -> Source | None:
    stmt = select(Source).where(Source.investigation_id == inv_id, Source.url_mac == mac)
    return (await db.execute(stmt)).scalar_one_or_none()


async def upsert_source(db: AsyncSession, cipher: FieldCipher, inv: Investigation, data: SourceInput) -> SourceUpsert:
    norm = normalize_url(data.url)
    mac = url_mac(cipher, norm.url)
    now = utcnow()
    existing = await _find_source(db, inv.id, mac)
    if existing is None:
        seq = await next_label(db, inv.id, "source_seq")  # takes the investigation row lock
        existing = await _find_source(db, inv.id, mac)  # re-check under the lock
        if existing is None:
            return await _insert_source(db, cipher, inv, data, norm.url, norm.host, norm.registrable_domain, mac, seq)
    existing.last_captured_at = now
    if existing.published_at is None and data.published_at is not None:
        existing.published_at = data.published_at
    if existing.access_status != "captured" and data.access_status == "captured":
        existing.access_status = "captured"
    return SourceUpsert(existing, False)


async def _insert_source(
    db: AsyncSession,
    cipher: FieldCipher,
    inv: Investigation,
    data: SourceInput,
    url: str,
    host: str,
    domain: str,
    mac: bytes,
    seq: int,
) -> SourceUpsert:
    sid = new_id()
    counts: dict[str, int] = {}
    title = None
    if data.title:
        red = redact_text(
            data.title[:MAX_TITLE_CHARS],
            mode=redaction_mode(inv),
            context=RedactionContext(source_kind=data.source_kind),
        )
        title, counts = red.text, dict(red.counts)
    archived = None
    if data.archived_url:
        archived = normalize_url(data.archived_url).url
    now = utcnow()
    source = Source(
        id=sid,
        investigation_id=inv.id,
        label_seq=seq,
        url=cipher.seal(url, table="sources", column="url", row_id=sid),
        url_mac=mac,
        host=host,
        registrable_domain=domain,
        source_category=data.category,
        connector_id=data.connector_id,
        title=cipher.seal_optional(title, table="sources", column="title", row_id=sid),
        title_tokens=tokens(cipher, title),
        publisher=(data.publisher or "")[:200] or None,
        ownership_group=data.ownership_group,
        published_at=data.published_at,
        first_captured_at=now,
        last_captured_at=now,
        reliability=data.reliability,
        archived_url=cipher.seal_optional(archived, table="sources", column="archived_url", row_id=sid),
        access_status=data.access_status,
        created_by=data.created_by,
    )
    db.add(source)
    await db.flush()
    return SourceUpsert(source, True, counts)


def source_view(cipher: FieldCipher, source: Source) -> dict[str, Any]:
    return {
        "id": str(source.id),
        "label": f"S-{source.label_seq}",
        "url": cipher.open(source.url, table="sources", column="url", row_id=source.id),
        "title": cipher.open_optional(source.title, table="sources", column="title", row_id=source.id),
        "host": source.host,
        "registrable_domain": source.registrable_domain,
        "category": source.source_category,
        "connector_id": source.connector_id,
        "publisher": source.publisher,
        "ownership_group": source.ownership_group,
        "published_at": source.published_at,
        "first_captured_at": source.first_captured_at,
        "last_captured_at": source.last_captured_at,
        "reliability": source.reliability,
        "archived_url": cipher.open_optional(
            source.archived_url, table="sources", column="archived_url", row_id=source.id
        ),
        "access_status": source.access_status,
    }


# --------------------------------------------------------------------------------------------------
# Evidence
# --------------------------------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class EvidenceInput:
    excerpt: str
    evidence_type: str
    provenance: str
    source_id: uuid.UUID | None = None
    origin_image_id: uuid.UUID | None = None
    collection_run_id: uuid.UUID | None = None
    captured_at: datetime | None = None
    published_at: datetime | None = None
    extra: dict[str, Any] | None = None
    country: str | None = None
    region: str | None = None
    credibility: int | None = None
    source_kind: SourceKind = SourceKind.WEB
    organization_context: bool = False
    created_by: uuid.UUID | None = None
    #: The excerpt was already redacted upstream (e.g. sanitized OCR output); still re-checked.
    pre_redacted_counts: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class EvidenceAdded:
    item: EvidenceItem
    created: bool
    redaction: RedactionResult


async def _find_evidence(
    db: AsyncSession, inv_id: uuid.UUID, source_id: uuid.UUID | None, image_id: uuid.UUID | None, mac: bytes
) -> EvidenceItem | None:
    stmt = select(EvidenceItem).where(
        EvidenceItem.investigation_id == inv_id,
        EvidenceItem.source_id.is_not_distinct_from(source_id),
        EvidenceItem.origin_image_id.is_not_distinct_from(image_id),
        EvidenceItem.content_mac == mac,
    )
    return (await db.execute(stmt)).scalar_one_or_none()


async def add_evidence(db: AsyncSession, cipher: FieldCipher, inv: Investigation, data: EvidenceInput) -> EvidenceAdded:
    if data.provenance not in EVIDENCE_PROVENANCES:
        raise ValueError("evidence provenance must be observed or source_reported")
    if data.source_id is None and data.origin_image_id is None:
        raise ValueError("evidence needs a source or an origin image")
    mode = redaction_mode(inv)
    context = RedactionContext(source_kind=data.source_kind, organization_context=data.organization_context)
    red = redact_text(data.excerpt[:MAX_EXCERPT_CHARS], mode=mode, context=context)
    excerpt = red.text.strip()
    if not excerpt:
        raise ValidationProblem("The evidence text is empty after redaction.", code="empty_evidence")
    mac = content_mac(cipher, normalized_for_mac(excerpt))
    existing = await _find_evidence(db, inv.id, data.source_id, data.origin_image_id, mac)
    if existing is not None:
        return EvidenceAdded(existing, False, red)
    seq = await next_label(db, inv.id, "evidence_seq")
    existing = await _find_evidence(db, inv.id, data.source_id, data.origin_image_id, mac)
    if existing is not None:
        return EvidenceAdded(existing, False, red)
    counts = dict(red.counts)
    for kind, n in data.pre_redacted_counts.items():
        counts[kind] = counts.get(kind, 0) + n
    extra_cipher = None
    eid = new_id()
    if data.extra:
        extra, extra_counts = redact_mapping(data.extra, mode=mode, context=context)
        for kind, n in extra_counts.items():
            counts[kind] = counts.get(kind, 0) + n
        extra_cipher = cipher.seal_json(extra, table="evidence_items", column="extra", row_id=eid)
    item = EvidenceItem(
        id=eid,
        investigation_id=inv.id,
        label_seq=seq,
        source_id=data.source_id,
        collection_run_id=data.collection_run_id,
        origin_image_id=data.origin_image_id,
        evidence_type=data.evidence_type,
        provenance=data.provenance,
        excerpt=cipher.seal(excerpt, table="evidence_items", column="excerpt", row_id=eid),
        extra=extra_cipher,
        content_mac=mac,
        simhash=keyed_simhash(cipher, excerpt),
        search_tokens=tokens(cipher, excerpt),
        captured_at=data.captured_at or utcnow(),
        published_at=data.published_at,
        country=data.country,
        region=data.region,
        credibility=data.credibility,
        sensitivity_flags=sorted(f.value for f in red.flags),
        redaction_counts=counts,
        created_by=data.created_by,
    )
    db.add(item)
    await db.flush()
    return EvidenceAdded(item, True, red)


def evidence_view(cipher: FieldCipher, item: EvidenceItem, *, reveal_sensitive: bool = False) -> dict[str, Any]:
    """Decrypted evidence for display. Medical-flagged text is hidden unless explicitly revealed."""
    hidden = bool(item.sensitivity_flags) and not reveal_sensitive
    excerpt = None if hidden else cipher.open(item.excerpt, table="evidence_items", column="excerpt", row_id=item.id)
    extra = None
    if item.extra is not None and not hidden:
        extra = cipher.open_json(item.extra, table="evidence_items", column="extra", row_id=item.id)
    return {
        "id": str(item.id),
        "label": f"E-{item.label_seq}",
        "source_id": str(item.source_id) if item.source_id else None,
        "origin_image_id": str(item.origin_image_id) if item.origin_image_id else None,
        "collection_run_id": str(item.collection_run_id) if item.collection_run_id else None,
        "evidence_type": item.evidence_type,
        "provenance": item.provenance,
        "excerpt": excerpt,
        "excerpt_hidden": hidden,
        "extra": extra,
        "captured_at": item.captured_at,
        "published_at": item.published_at,
        "country": item.country,
        "region": item.region,
        "credibility": item.credibility,
        "sensitivity_flags": list(item.sensitivity_flags),
        "redaction_counts": dict(item.redaction_counts),
        "syndication_cluster_id": str(item.syndication_cluster_id) if item.syndication_cluster_id else None,
        "created_at": item.created_at,
    }
