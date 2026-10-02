"""Build the evidence documents the assistant may read and cite.

Each evidence item becomes one document: the redacted excerpt (citable) plus provenance metadata (not citable).
Evidence flagged as sensitive (e.g. medical) is never sent to the provider. Without an explicit selection the most
relevant items are chosen by term overlap with the request, newest first on ties.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from angel_engine.ai.types import ContextDoc
from angel_engine.crypto.envelope import FieldCipher
from angel_engine.db.models import EvidenceItem, Finding, FindingEvidence, Image, Investigation, Source

MAX_DOC_CHARS = 6000
MAX_TOTAL_CHARS = 200_000
MAX_CANDIDATES = 2000
PROVENANCE_LABELS = {"observed": "observed by Angel Engine", "source_reported": "reported by the source"}
STATUS_LABELS = {
    "confirmed_by_source": "confirmed by source",
    "corroborated": "corroborated",
    "unverified": "unverified",
    "contradicted": "contradicted",
    "ai_hypothesis": "AI hypothesis",
}
_WORD = re.compile(r"[^\W_]{3,}", re.UNICODE)
_STOP_WORDS = (
    "the and for with that this from what when where which who whom whose why how are was were has have had not "
    "but you your our their its about into over under than then them they there these those does did any all can "
    "could would should may might will shall evidence source sources document documents investigation"
)
_STOP = frozenset(_STOP_WORDS.split())


def terms(text: str) -> set[str]:
    return {w for w in (m.group(0).casefold() for m in _WORD.finditer(text)) if w not in _STOP}


def _clip(text: str) -> str:
    text = text.strip()
    return text if len(text) <= MAX_DOC_CHARS else text[: MAX_DOC_CHARS - 1].rsplit(" ", 1)[0] + "…"


async def build_context(
    db: AsyncSession,
    cipher: FieldCipher,
    inv: Investigation,
    *,
    query: str,
    evidence_ids: Sequence[uuid.UUID] = (),
    finding_ids: Sequence[uuid.UUID] = (),
    image_id: uuid.UUID | None = None,
    limit: int = 120,
) -> list[ContextDoc]:
    stmt = (
        select(EvidenceItem, Source)
        .outerjoin(Source, Source.id == EvidenceItem.source_id)
        .where(EvidenceItem.investigation_id == inv.id)
    )
    selected = bool(evidence_ids or finding_ids or image_id)
    if evidence_ids:
        stmt = stmt.where(EvidenceItem.id.in_(list(evidence_ids)))
    elif finding_ids:
        stmt = stmt.where(
            EvidenceItem.id.in_(
                select(FindingEvidence.evidence_id).where(
                    FindingEvidence.finding_id.in_(list(finding_ids)), FindingEvidence.dismissed_at.is_(None)
                )
            )
        )
    elif image_id:
        stmt = stmt.where(EvidenceItem.origin_image_id == image_id)
    rows = (await db.execute(stmt.order_by(EvidenceItem.captured_at.desc()).limit(MAX_CANDIDATES))).all()
    images = {
        i.id: i.label_seq
        for i in (
            await db.execute(select(Image).where(Image.investigation_id == inv.id).limit(MAX_CANDIDATES))
        ).scalars()
    }
    wanted = terms(query)
    candidates: list[tuple[float, EvidenceItem, Source | None, str]] = []
    for item, source in rows:
        if item.sensitivity_flags:  # medical and other sensitive evidence never leaves the system
            continue
        text = cipher.open(item.excerpt, table="evidence_items", column="excerpt", row_id=item.id)
        score = len(wanted & terms(text)) + (0.5 * len(wanted & terms(source.host)) if source else 0)
        candidates.append((score, item, source, text))
    if not selected and wanted:
        candidates.sort(key=lambda c: (-c[0], -(c[1].captured_at.timestamp() if c[1].captured_at else 0)))
    chosen = candidates[:limit]
    findings = await _finding_labels(db, inv, [c[1].id for c in chosen])
    docs: list[ContextDoc] = []
    total = 0
    for _, item, origin, text in sorted(chosen, key=lambda c: c[1].label_seq):
        clipped = _clip(text)
        if total + len(clipped) > MAX_TOTAL_CHARS:
            break
        total += len(clipped)
        docs.append(_doc(cipher, item, origin, clipped, images, findings.get(item.id, [])))
    return docs


async def _finding_labels(db: AsyncSession, inv: Investigation, ids: list[uuid.UUID]) -> dict[uuid.UUID, list[str]]:
    if not ids:
        return {}
    rows = await db.execute(
        select(FindingEvidence.evidence_id, Finding.label_seq, Finding.verification_status)
        .join(Finding, Finding.id == FindingEvidence.finding_id)
        .where(Finding.investigation_id == inv.id, FindingEvidence.evidence_id.in_(ids))
    )
    out: dict[uuid.UUID, list[str]] = {}
    for evidence_id, seq, status in rows:
        out.setdefault(evidence_id, []).append(f"F-{seq} ({STATUS_LABELS.get(status, status)})")
    return out


def _doc(
    cipher: FieldCipher,
    item: EvidenceItem,
    source: Source | None,
    text: str,
    images: dict[uuid.UUID, int],
    findings: list[str],
) -> ContextDoc:
    label = f"E-{item.label_seq}"
    origin = source.host if source else f"image I-{images.get(item.origin_image_id, '?')}"  # type: ignore[arg-type]
    when = (item.published_at or item.captured_at).date().isoformat() if (item.published_at or item.captured_at) else ""
    parts = [
        f"Evidence {label}",
        f"type: {item.evidence_type.replace('_', ' ')}",
        f"provenance: {PROVENANCE_LABELS.get(item.provenance, item.provenance)}",
        f"origin: {origin}",
    ]
    if item.published_at:
        parts.append(f"published: {item.published_at.date().isoformat()}")
    if item.captured_at:
        parts.append(f"captured: {item.captured_at.date().isoformat()}")
    if findings:
        parts.append("cited by findings: " + ", ".join(findings[:5]))
    url = cipher.open(source.url, table="sources", column="url", row_id=source.id) if source else None
    return ContextDoc(
        evidence_id=item.id,
        label=label,
        title=" · ".join(p for p in (label, origin, when) if p),
        context="; ".join(parts),
        text=text,
        source_url=url,
        captured_at=item.captured_at,
    )
