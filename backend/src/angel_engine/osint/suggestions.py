"""System suggestions for reviewers: syndicated copies, corroborations and contradictions.

Suggestions are never applied to findings automatically. The only automatic effect is conservative:
evidence detected as a syndicated copy joins a syndication cluster, so the copies count as *one* origin
when corroboration is evaluated (a reviewer can dismiss the suggestion to undo that).
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Sequence
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from angel_engine.core.ids import new_id
from angel_engine.crypto.envelope import FieldCipher
from angel_engine.db.models import Entity, EvidenceItem, Fact, FindingEvidence, Investigation, Source, Suggestion
from angel_engine.evidence.independence import origin_key
from angel_engine.evidence.simhash import NEAR_DUPLICATE_BITS, distance
from angel_engine.evidence.urls import UrlError, normalize_url
from angel_engine.osint import facts as fx

RULE_VERSION = "2026.10"


async def _add(
    db: AsyncSession,
    cipher: FieldCipher,
    inv: Investigation,
    *,
    kind: str,
    rule_id: str,
    message: str,
    dedupe_key: str,
    evidence_ids: Sequence[uuid.UUID] = (),
    fact_ids: Sequence[uuid.UUID] = (),
    finding_ids: Sequence[uuid.UUID] = (),
) -> Suggestion | None:
    existing = (
        await db.execute(
            select(Suggestion.id).where(Suggestion.investigation_id == inv.id, Suggestion.dedupe_key == dedupe_key)
        )
    ).first()
    if existing is not None:
        return None
    sid = new_id()
    suggestion = Suggestion(
        id=sid,
        investigation_id=inv.id,
        kind=kind,
        rule_id=rule_id,
        rule_version=RULE_VERSION,
        message=cipher.seal(message, table="suggestions", column="message", row_id=sid),
        dedupe_key=dedupe_key,
        evidence_ids=list(evidence_ids),
        fact_ids=list(fact_ids),
        finding_ids=list(finding_ids),
    )
    db.add(suggestion)
    await db.flush()
    return suggestion


async def _findings_citing(db: AsyncSession, evidence_ids: Iterable[uuid.UUID]) -> list[uuid.UUID]:
    ids = list(evidence_ids)
    if not ids:
        return []
    rows = await db.execute(select(FindingEvidence.finding_id).where(FindingEvidence.evidence_id.in_(ids)))
    return list(dict.fromkeys(rows.scalars()))


def _key(*ids: uuid.UUID) -> str:
    return ":".join(sorted(str(i) for i in ids))


# --------------------------------------------------------------------------------------------------
# Syndication
# --------------------------------------------------------------------------------------------------
async def detect_syndication(
    db: AsyncSession, cipher: FieldCipher, inv: Investigation, new_ids: Sequence[uuid.UUID]
) -> int:
    if not new_ids:
        return 0
    rows = (
        await db.execute(
            select(EvidenceItem, Source)
            .outerjoin(Source, Source.id == EvidenceItem.source_id)
            .where(EvidenceItem.investigation_id == inv.id)
        )
    ).all()
    by_id = {ev.id: (ev, src) for ev, src in rows}
    url_to_evidence: dict[str, uuid.UUID] = {}
    for ev, src in rows:
        if src is not None:
            url_to_evidence[cipher.open(src.url, table="sources", column="url", row_id=src.id)] = ev.id
    created = 0
    for new_id_ in new_ids:
        if new_id_ not in by_id:
            continue
        ev, src = by_id[new_id_]
        pairs: list[tuple[uuid.UUID, str]] = []
        if ev.simhash is not None:
            for other, other_src in by_id.values():
                if (
                    other.id != ev.id
                    and other.simhash is not None
                    and distance(ev.simhash, other.simhash) <= NEAR_DUPLICATE_BITS
                    and origin_key(ev, src) != origin_key(other, other_src)
                ):
                    pairs.append((other.id, "simhash"))
        extra = cipher.open_json(ev.extra, table="evidence_items", column="extra", row_id=ev.id) if ev.extra else {}
        for field in ("is_based_on", "canonical_url"):
            target = extra.get(field) if isinstance(extra, dict) else None
            if isinstance(target, str):
                try:
                    canonical = normalize_url(target).url
                except UrlError:
                    continue
                other_id = url_to_evidence.get(canonical)
                if other_id is not None and other_id != ev.id:
                    pairs.append((other_id, field))
        for other_id, rule in pairs:
            other = by_id[other_id][0]
            cluster = other.syndication_cluster_id or ev.syndication_cluster_id or new_id()
            await db.execute(
                update(EvidenceItem)
                .where(EvidenceItem.id.in_([ev.id, other.id]))
                .values(syndication_cluster_id=cluster)
            )
            ev.syndication_cluster_id = other.syndication_cluster_id = cluster
            if await _add(
                db,
                cipher,
                inv,
                kind="syndication",
                rule_id=f"syndication.{rule}",
                message=f"E-{other.label_seq} and E-{ev.label_seq} appear to be copies of the same "
                "text, so they count as one origin when corroborating a finding.",
                dedupe_key=f"syn:{_key(ev.id, other.id)}",
                evidence_ids=[other.id, ev.id],
                finding_ids=await _findings_citing(db, [ev.id, other.id]),
            ):
                created += 1
    return created


# --------------------------------------------------------------------------------------------------
# Facts: corroboration and contradiction
# --------------------------------------------------------------------------------------------------
async def _fact_rows(db: AsyncSession, inv: Investigation) -> list[tuple[Fact, EvidenceItem, Source | None]]:
    rows = (
        await db.execute(
            select(Fact, EvidenceItem, Source)
            .join(EvidenceItem, EvidenceItem.id == Fact.evidence_id)
            .outerjoin(Source, Source.id == EvidenceItem.source_id)
            .where(Fact.investigation_id == inv.id)
        )
    ).all()
    return [(f, ev, src) for f, ev, src in rows]


async def compare_facts(
    db: AsyncSession, cipher: FieldCipher, inv: Investigation, new_fact_ids: Sequence[uuid.UUID]
) -> dict[str, int]:
    counts = {"contradictions": 0, "corroborations": 0}
    if not new_fact_ids:
        return counts
    rows = await _fact_rows(db, inv)
    entity_names = {
        e.id: e for e in (await db.execute(select(Entity).where(Entity.investigation_id == inv.id))).scalars()
    }
    values: dict[uuid.UUID, Any] = {
        f.id: cipher.open_json(f.value, table="facts", column="value", row_id=f.id) for f, _, _ in rows
    }
    new = set(new_fact_ids)
    for fact, ev, src in rows:
        if fact.id not in new or fact.entity_id is None or fact.attribute not in fx.ATTRIBUTES:
            continue
        mine = fx.interval(str(values[fact.id]), fact.precision)
        if mine is None:
            continue
        label = fx.ATTRIBUTES[fact.attribute][0]
        entity = entity_names.get(fact.entity_id)
        who = (entity.name or "the entity") if entity else "the entity"
        for other, other_ev, other_src in rows:
            if (
                other.id == fact.id
                or other.entity_id != fact.entity_id
                or not fx.comparable(fact.attribute, other.attribute)
            ):
                continue
            theirs = fx.interval(str(values[other.id]), other.precision)
            if theirs is None or other.evidence_id == fact.evidence_id:
                continue
            evidence_ids = [other.evidence_id, fact.evidence_id]
            findings = await _findings_citing(db, evidence_ids)
            if not fx.overlaps(mine, theirs):
                if await _add(
                    db,
                    cipher,
                    inv,
                    kind="contradiction",
                    rule_id=f"contradiction.{fact.attribute}",
                    message=f"E-{other_ev.label_seq} and E-{ev.label_seq} disagree on “{label}” for {who}: "
                    f"{values[other.id]} vs {values[fact.id]}. Review both sources before changing "
                    "any finding.",
                    dedupe_key=f"con:{_key(fact.id, other.id)}",
                    evidence_ids=evidence_ids,
                    fact_ids=[other.id, fact.id],
                    finding_ids=findings,
                ):
                    counts["contradictions"] += 1
            elif origin_key(ev, src) != origin_key(other_ev, other_src) and await _add(
                db,
                cipher,
                inv,
                kind="corroboration",
                rule_id=f"corroboration.{fact.attribute}",
                message=f"E-{other_ev.label_seq} and E-{ev.label_seq} independently agree on “{label}” "
                f"for {who} ({values[fact.id]}).",
                dedupe_key=f"cor:{_key(fact.id, other.id)}",
                evidence_ids=evidence_ids,
                fact_ids=[other.id, fact.id],
                finding_ids=findings,
            ):
                counts["corroborations"] += 1
    return counts
