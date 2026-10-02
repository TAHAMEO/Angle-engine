"""Evidence graph: relationships between public entities, each supported by at least one evidence item.

* Relationship types come from an allowlist, with endpoint-type rules so edges stay meaningful.
* An edge is created with at least one evidence link (deferred database constraint) and disappears
  together with its last link (database trigger).
* Verification status changes are human actions with the same evidence rules as findings; AI-proposed
  edges start as ``ai_hypothesis``.
"""

from __future__ import annotations

import uuid
from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import delete, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from angel_engine.core.clock import utcnow
from angel_engine.core.enums import EntityType, Provenance, RelationshipType, Stance, VerificationStatus
from angel_engine.core.ids import new_id
from angel_engine.core.problems import ConflictState, ValidationProblem
from angel_engine.crypto.envelope import FieldCipher
from angel_engine.db.models import (
    Entity,
    EvidenceItem,
    Investigation,
    Relationship,
    RelationshipEvidence,
    RelationshipStatusHistory,
    Source,
)
from angel_engine.db.session import allow_status_transition
from angel_engine.entities.service import entity_name
from angel_engine.evidence.independence import origin_key

E = EntityType
V = VerificationStatus
MAX_DEPTH = 3
MAX_NODES = 400
MIN_JUSTIFICATION = 20

#: rel_type → (allowed source types, allowed target types); None = any type.
REL_RULES: dict[str, tuple[frozenset[str] | None, frozenset[str] | None]] = {
    RelationshipType.SHOWS_TEXT: (frozenset({E.IMAGE}), None),
    RelationshipType.DEPICTS: (frozenset({E.IMAGE}), frozenset({E.LANDMARK, E.BRAND, E.PRODUCT, E.LOCATION,
                                                               E.ORGANIZATION, E.EVENT})),
    RelationshipType.LINKS_TO: (frozenset({E.WEBPAGE, E.WEBSITE, E.DOCUMENT, E.USERNAME, E.IMAGE}), None),
    RelationshipType.HOSTED_ON: (frozenset({E.WEBPAGE, E.DOCUMENT, E.IMAGE}), frozenset({E.WEBSITE, E.DOMAIN})),
    RelationshipType.OPERATED_BY: (frozenset({E.WEBSITE, E.DOMAIN, E.USERNAME, E.BRAND, E.PRODUCT}),
                                   frozenset({E.ORGANIZATION, E.PUBLIC_FIGURE})),
    RelationshipType.REGISTERED_BY: (frozenset({E.DOMAIN, E.WEBSITE}), frozenset({E.ORGANIZATION})),
    RelationshipType.SUBSIDIARY_OF: (frozenset({E.ORGANIZATION}), frozenset({E.ORGANIZATION})),
    RelationshipType.MENTIONS: (None, None),
    RelationshipType.PUBLISHED_BY: (frozenset({E.WEBPAGE, E.DOCUMENT, E.IMAGE}),
                                    frozenset({E.ORGANIZATION, E.WEBSITE, E.USERNAME, E.PUBLIC_FIGURE})),
    RelationshipType.PARTICIPATED_IN: (frozenset({E.ORGANIZATION, E.PUBLIC_FIGURE, E.BRAND}), frozenset({E.EVENT})),
    RelationshipType.LOCATED_IN: (frozenset({E.ORGANIZATION, E.LANDMARK, E.EVENT, E.IMAGE, E.LOCATION}),
                                  frozenset({E.LOCATION})),
    RelationshipType.SAME_IMAGE_AS: (frozenset({E.IMAGE}), frozenset({E.IMAGE})),
    RelationshipType.SIMILAR_IMAGE_TO: (frozenset({E.IMAGE}), frozenset({E.IMAGE})),
    RelationshipType.DOCUMENTED_BY: (None, frozenset({E.DOCUMENT, E.WEBPAGE})),
}  # fmt: skip

STATUS_LABELS = {
    V.CONFIRMED_BY_SOURCE.value: "Confirmed by source",
    V.CORROBORATED.value: "Corroborated",
    V.UNVERIFIED.value: "Unverified",
    V.CONTRADICTED.value: "Contradicted",
    V.AI_HYPOTHESIS.value: "AI hypothesis",
}


def check_types(rel_type: str, from_type: str, to_type: str) -> None:
    if rel_type not in REL_RULES:
        raise ValidationProblem("Unknown relationship type.", code="invalid_relationship_type")
    sources, targets = REL_RULES[rel_type]
    if (sources is not None and from_type not in sources) or (targets is not None and to_type not in targets):
        raise ValidationProblem(
            f"A {from_type.replace('_', ' ')} cannot be “{rel_type.replace('_', ' ')}” a {to_type.replace('_', ' ')}.",
            code="relationship_type_mismatch",
        )


# --------------------------------------------------------------------------------------------------
# Creation and evidence links
# --------------------------------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class RelationshipInput:
    from_entity_id: uuid.UUID
    rel_type: str
    to_entity_id: uuid.UUID
    evidence_ids: tuple[uuid.UUID, ...]
    stance: str = Stance.SUPPORTS.value
    provenance: str = Provenance.SOURCE_REPORTED.value
    confidence: str | None = None
    created_via: str = "system"
    created_by: uuid.UUID | None = None


async def _entities(db: AsyncSession, inv_id: uuid.UUID, ids: Sequence[uuid.UUID]) -> dict[uuid.UUID, Entity]:
    rows = (await db.execute(select(Entity).where(Entity.investigation_id == inv_id, Entity.id.in_(ids)))).scalars()
    return {e.id: e for e in rows}


async def _check_evidence(db: AsyncSession, inv_id: uuid.UUID, ids: Sequence[uuid.UUID]) -> None:
    found = set(
        (
            await db.execute(
                select(EvidenceItem.id).where(EvidenceItem.investigation_id == inv_id, EvidenceItem.id.in_(ids))
            )
        ).scalars()
    )
    missing = [str(i) for i in ids if i not in found]
    if missing:
        raise ValidationProblem(
            "Some cited evidence items do not exist in this investigation.",
            code="unknown_evidence",
            evidence_ids=missing,
        )


async def link_evidence(
    db: AsyncSession, inv: Investigation, relationship: Relationship, evidence_ids: Sequence[uuid.UUID], stance: str
) -> int:
    if stance not in {s.value for s in Stance}:
        raise ValidationProblem("Unknown stance.", code="invalid_stance")
    await _check_evidence(db, inv.id, evidence_ids)
    existing = set(
        (
            await db.execute(
                select(RelationshipEvidence.evidence_id).where(
                    RelationshipEvidence.relationship_id == relationship.id, RelationshipEvidence.stance == stance
                )
            )
        ).scalars()
    )
    added = 0
    for evidence_id in dict.fromkeys(evidence_ids):
        if evidence_id in existing:
            continue
        db.add(
            RelationshipEvidence(
                id=new_id(),
                investigation_id=inv.id,
                relationship_id=relationship.id,
                evidence_id=evidence_id,
                stance=stance,
            )
        )
        added += 1
    await db.flush()
    return added


async def upsert_relationship(
    db: AsyncSession, inv: Investigation, data: RelationshipInput
) -> tuple[Relationship, bool]:
    if not data.evidence_ids:
        raise ValidationProblem("A relationship must cite at least one evidence item.", code="evidence_required")
    if data.from_entity_id == data.to_entity_id:
        raise ValidationProblem("A relationship needs two different entities.", code="self_relationship")
    entities = await _entities(db, inv.id, [data.from_entity_id, data.to_entity_id])
    if len(entities) != 2:
        raise ValidationProblem("Both entities must exist in this investigation.", code="unknown_entity")
    source, target = entities[data.from_entity_id], entities[data.to_entity_id]
    check_types(data.rel_type, source.type, target.type)
    stmt = select(Relationship).where(
        Relationship.investigation_id == inv.id,
        Relationship.from_entity_id == source.id,
        Relationship.rel_type == data.rel_type,
        Relationship.to_entity_id == target.id,
    )
    existing = (await db.execute(stmt)).scalar_one_or_none()
    if existing is not None:
        await link_evidence(db, inv, existing, data.evidence_ids, data.stance)
        return existing, False
    status = V.AI_HYPOTHESIS.value if data.provenance == Provenance.AI_HYPOTHESIS.value else V.UNVERIFIED.value
    rel = Relationship(
        id=new_id(),
        investigation_id=inv.id,
        from_entity_id=source.id,
        to_entity_id=target.id,
        rel_type=data.rel_type,
        provenance=data.provenance,
        verification_status=status,
        confidence=data.confidence,
        created_by=data.created_by,
        created_via=data.created_via,
    )
    db.add(rel)
    await db.flush()
    await link_evidence(db, inv, rel, data.evidence_ids, data.stance)
    db.add(
        RelationshipStatusHistory(
            id=new_id(),
            investigation_id=inv.id,
            relationship_id=rel.id,
            from_status=None,
            to_status=status,
            actor_id=data.created_by,
            evidence_ids=list(data.evidence_ids),
            precondition_snapshot={"event": "created", "created_via": data.created_via},
        )
    )
    await db.flush()
    return rel, True


async def repoint_relationships(db: AsyncSession, inv: Investigation, old: uuid.UUID, new: uuid.UUID) -> int:
    """Move every edge of entity ``old`` to entity ``new`` (entity merge)."""
    rows = (
        (
            await db.execute(
                select(Relationship).where(
                    Relationship.investigation_id == inv.id,
                    or_(Relationship.from_entity_id == old, Relationship.to_entity_id == old),
                )
            )
        )
        .scalars()
        .all()
    )
    moved = 0
    for rel in rows:
        src = new if rel.from_entity_id == old else rel.from_entity_id
        dst = new if rel.to_entity_id == old else rel.to_entity_id
        if src == dst:
            await db.delete(rel)  # would become a self-loop; its history goes with it
            continue
        twin = (
            await db.execute(
                select(Relationship).where(
                    Relationship.investigation_id == inv.id,
                    Relationship.from_entity_id == src,
                    Relationship.rel_type == rel.rel_type,
                    Relationship.to_entity_id == dst,
                    Relationship.id != rel.id,
                )
            )
        ).scalar_one_or_none()
        if twin is not None:
            links = (
                (await db.execute(select(RelationshipEvidence).where(RelationshipEvidence.relationship_id == rel.id)))
                .scalars()
                .all()
            )
            for link in links:
                await link_evidence(db, inv, twin, [link.evidence_id], link.stance)
            await db.delete(rel)
        else:
            rel.from_entity_id, rel.to_entity_id = src, dst
        moved += 1
    await db.flush()
    return moved


async def unlink_evidence(db: AsyncSession, relationship: Relationship, evidence_id: uuid.UUID) -> bool:
    """Remove one evidence link. Returns True when the edge itself was removed (it lost its last support)."""
    await db.execute(
        delete(RelationshipEvidence).where(
            RelationshipEvidence.relationship_id == relationship.id, RelationshipEvidence.evidence_id == evidence_id
        )
    )
    await db.flush()
    gone = (await db.execute(select(Relationship.id).where(Relationship.id == relationship.id))).first() is None
    if not gone:
        await recheck(db, relationship)
    return gone


# --------------------------------------------------------------------------------------------------
# Transitions
# --------------------------------------------------------------------------------------------------
async def _links(db: AsyncSession, rel_id: uuid.UUID) -> list[tuple[RelationshipEvidence, EvidenceItem, Source | None]]:
    rows = (
        await db.execute(
            select(RelationshipEvidence, EvidenceItem, Source)
            .join(EvidenceItem, EvidenceItem.id == RelationshipEvidence.evidence_id)
            .outerjoin(Source, Source.id == EvidenceItem.source_id)
            .where(RelationshipEvidence.relationship_id == rel_id)
        )
    ).all()
    return [(link, ev, src) for link, ev, src in rows]


def evaluate(
    rel: Relationship, links: Sequence[tuple[RelationshipEvidence, EvidenceItem, Source | None]]
) -> tuple[tuple[str, ...], dict[str, list[str]], dict[str, Any]]:
    support = [(ev, src) for link, ev, src in links if link.stance == Stance.SUPPORTS.value]
    contra = [link for link, _, _ in links if link.stance == Stance.CONTRADICTS.value]
    origins = {origin_key(ev, src) for ev, src in support}
    failed: dict[str, list[str]] = {}
    if not support:
        failed.setdefault(V.CONFIRMED_BY_SOURCE.value, []).append("Needs at least one supporting evidence item.")
    if len(origins) < 2:
        failed.setdefault(V.CORROBORATED.value, []).append(
            "Needs supporting evidence from at least two independent origins."
        )
    if contra:
        for target in (V.CONFIRMED_BY_SOURCE.value, V.CORROBORATED.value):
            failed.setdefault(target, []).append("Contradicting evidence is linked; remove or resolve it first.")
    else:
        failed.setdefault(V.CONTRADICTED.value, []).append("Needs at least one contradicting evidence item.")
    if rel.provenance != Provenance.AI_HYPOTHESIS.value:
        failed.setdefault(V.AI_HYPOTHESIS.value, []).append(
            "Only AI-proposed relationships can carry the AI-hypothesis status."
        )
    allowed = tuple(s.value for s in V if s.value != rel.verification_status and s.value not in failed)
    snapshot = {
        "supporting_links": len(support),
        "independent_origins": len(origins),
        "contradicting_links": len(contra),
    }
    return allowed, failed, snapshot


async def _set_status(
    db: AsyncSession,
    cipher: FieldCipher,
    rel: Relationship,
    to_status: str,
    *,
    actor_id: uuid.UUID | None,
    justification: str | None,
    evidence_ids: Sequence[uuid.UUID],
    snapshot: dict[str, Any],
) -> str:
    previous = rel.verification_status
    await allow_status_transition(db)
    rel.verification_status = to_status
    rel.updated_at = utcnow()
    await db.flush()
    await db.execute(text("SELECT set_config('ae.transition', 'off', true)"))
    hid = new_id()
    db.add(
        RelationshipStatusHistory(
            id=hid,
            investigation_id=rel.investigation_id,
            relationship_id=rel.id,
            from_status=previous,
            to_status=to_status,
            actor_id=actor_id,
            justification=cipher.seal_optional(
                justification, table="relationship_status_history", column="justification", row_id=hid
            ),
            evidence_ids=list(evidence_ids),
            precondition_snapshot=snapshot,
        )
    )
    await db.flush()
    return previous


async def transition(
    db: AsyncSession,
    cipher: FieldCipher,
    rel: Relationship,
    to_status: str,
    justification: str,
    evidence_ids: Sequence[uuid.UUID],
    *,
    actor_id: uuid.UUID,
    independence_attested: bool,
) -> str:
    if to_status not in STATUS_LABELS:
        raise ValidationProblem("Unknown verification status.", code="invalid_status")
    if len(justification.strip()) < MIN_JUSTIFICATION:
        raise ValidationProblem(
            f"Explain the change in at least {MIN_JUSTIFICATION} characters.", code="justification_required"
        )
    links = await _links(db, rel.id)
    allowed, failed, snapshot = evaluate(rel, links)
    if to_status not in allowed:
        raise ConflictState(
            f"This relationship cannot move to “{STATUS_LABELS[to_status]}” yet.",
            code="transition_not_allowed",
            allowed_transitions=list(allowed),
            failed_preconditions=failed.get(to_status, ["It already has this status."]),
        )
    linked = {ev.id for _, ev, _ in links}
    unknown = [str(e) for e in evidence_ids if e not in linked]
    if unknown:
        raise ValidationProblem(
            "Cite evidence items that are linked to this relationship.",
            code="evidence_not_linked",
            evidence_ids=unknown,
        )
    if to_status == V.CORROBORATED.value and not independence_attested:
        raise ValidationProblem(
            "Confirm that the corroborating sources are independent of each other.",
            code="independence_attestation_required",
        )
    return await _set_status(
        db,
        cipher,
        rel,
        to_status,
        actor_id=actor_id,
        justification=justification.strip(),
        evidence_ids=evidence_ids,
        snapshot={**snapshot, "independence_attested": independence_attested},
    )


async def recheck(db: AsyncSession, rel: Relationship) -> str | None:
    if rel.verification_status not in (V.CONFIRMED_BY_SOURCE.value, V.CORROBORATED.value, V.CONTRADICTED.value):
        return None
    _, failed, snapshot = evaluate(rel, await _links(db, rel.id))
    if rel.verification_status not in failed:
        return None
    await allow_status_transition(db)
    previous = rel.verification_status
    rel.verification_status = V.UNVERIFIED.value
    await db.flush()
    await db.execute(text("SELECT set_config('ae.transition', 'off', true)"))
    db.add(
        RelationshipStatusHistory(
            id=new_id(),
            investigation_id=rel.investigation_id,
            relationship_id=rel.id,
            from_status=previous,
            to_status=V.UNVERIFIED.value,
            actor_id=None,
            precondition_snapshot={**snapshot, "automatic": True, "reason": failed[previous]},
        )
    )
    await db.flush()
    return V.UNVERIFIED.value


# --------------------------------------------------------------------------------------------------
# Queries
# --------------------------------------------------------------------------------------------------
async def _edge_sources(db: AsyncSession, rel_ids: Sequence[uuid.UUID]) -> dict[uuid.UUID, list[dict[str, Any]]]:
    if not rel_ids:
        return {}
    rows = (
        await db.execute(
            select(
                RelationshipEvidence.relationship_id,
                RelationshipEvidence.stance,
                EvidenceItem.id,
                EvidenceItem.label_seq,
                Source.id,
                Source.label_seq,
                Source.host,
            )
            .join(EvidenceItem, EvidenceItem.id == RelationshipEvidence.evidence_id)
            .outerjoin(Source, Source.id == EvidenceItem.source_id)
            .where(RelationshipEvidence.relationship_id.in_(rel_ids))
        )
    ).all()
    out: dict[uuid.UUID, list[dict[str, Any]]] = {}
    for rel_id, stance, ev_id, ev_seq, src_id, src_seq, host in rows:
        out.setdefault(rel_id, []).append(
            {
                "stance": stance,
                "evidence_id": str(ev_id),
                "evidence_label": f"E-{ev_seq}",
                "source_id": str(src_id) if src_id else None,
                "source_label": f"S-{src_seq}" if src_seq else None,
                "host": host,
            }
        )
    return out


def _node(cipher: FieldCipher, entity: Entity) -> dict[str, Any]:
    return {
        "id": str(entity.id),
        "type": entity.type,
        "name": entity_name(cipher, entity),
        "country": entity.country,
        "location_level": entity.location_level,
    }


def _edge(rel: Relationship, support: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "id": str(rel.id),
        "from": str(rel.from_entity_id),
        "to": str(rel.to_entity_id),
        "rel_type": rel.rel_type,
        "provenance": rel.provenance,
        "verification_status": rel.verification_status,
        "confidence": rel.confidence,
        "supporting_count": sum(1 for s in support if s["stance"] == "supports"),
        "contradicting_count": sum(1 for s in support if s["stance"] == "contradicts"),
        "evidence": support,
    }


async def subgraph(
    db: AsyncSession,
    cipher: FieldCipher,
    inv: Investigation,
    *,
    root: uuid.UUID | None = None,
    depth: int = 2,
    statuses: Sequence[str] | None = None,
    rel_types: Sequence[str] | None = None,
    entity_types: Sequence[str] | None = None,
) -> dict[str, Any]:
    depth = max(1, min(MAX_DEPTH, depth))
    stmt = select(Relationship).where(Relationship.investigation_id == inv.id)
    if statuses:
        stmt = stmt.where(Relationship.verification_status.in_(list(statuses)))
    if rel_types:
        stmt = stmt.where(Relationship.rel_type.in_(list(rel_types)))
    rels = list((await db.execute(stmt)).scalars())
    entity_rows = (
        await db.execute(select(Entity).where(Entity.investigation_id == inv.id, Entity.merged_into_id.is_(None)))
    ).scalars()
    entities = {e.id: e for e in entity_rows}
    if entity_types:
        allowed = set(entity_types)
        rels = [
            r
            for r in rels
            if entities.get(r.from_entity_id)
            and entities.get(r.to_entity_id)
            and entities[r.from_entity_id].type in allowed
            and entities[r.to_entity_id].type in allowed
        ]
    node_ids: set[uuid.UUID]
    if root is not None:
        if root not in entities:
            from angel_engine.core.problems import NotFound

            raise NotFound()
        adjacency: dict[uuid.UUID, list[Relationship]] = {}
        for rel in rels:
            adjacency.setdefault(rel.from_entity_id, []).append(rel)
            adjacency.setdefault(rel.to_entity_id, []).append(rel)
        node_ids, frontier, keep = {root}, deque([(root, 0)]), set()
        while frontier and len(node_ids) < MAX_NODES:
            current, d = frontier.popleft()
            if d >= depth:
                continue
            for rel in adjacency.get(current, []):
                keep.add(rel.id)
                other = rel.to_entity_id if rel.from_entity_id == current else rel.from_entity_id
                if other not in node_ids:
                    node_ids.add(other)
                    frontier.append((other, d + 1))
        rels = [r for r in rels if r.id in keep]
    else:
        rels = rels[: MAX_NODES * 2]
        node_ids = {r.from_entity_id for r in rels} | {r.to_entity_id for r in rels}
        if not rels:
            node_ids = set(list(entities)[:MAX_NODES])
    support = await _edge_sources(db, [r.id for r in rels])
    return {
        "nodes": [_node(cipher, entities[n]) for n in node_ids if n in entities][:MAX_NODES],
        "edges": [_edge(r, support.get(r.id, [])) for r in rels],
        "truncated": len(node_ids) >= MAX_NODES,
    }


async def shortest_path(
    db: AsyncSession, inv: Investigation, start: uuid.UUID, goal: uuid.UUID, *, max_depth: int = 4
) -> list[uuid.UUID] | None:
    """Relationship ids along the shortest undirected path between two entities (or None)."""
    rels = (await db.execute(select(Relationship).where(Relationship.investigation_id == inv.id))).scalars().all()
    adjacency: dict[uuid.UUID, list[tuple[uuid.UUID, uuid.UUID]]] = {}
    for rel in rels:
        adjacency.setdefault(rel.from_entity_id, []).append((rel.to_entity_id, rel.id))
        adjacency.setdefault(rel.to_entity_id, []).append((rel.from_entity_id, rel.id))
    previous: dict[uuid.UUID, tuple[uuid.UUID, uuid.UUID] | None] = {start: None}
    frontier = deque([(start, 0)])
    while frontier:
        node, d = frontier.popleft()
        if node == goal:
            path: list[uuid.UUID] = []
            step = previous[node]
            while step is not None:
                path.append(step[1])
                step = previous[step[0]]
            return list(reversed(path))
        if d >= max_depth:
            continue
        for neighbour, rel_id in adjacency.get(node, []):
            if neighbour not in previous:
                previous[neighbour] = (node, rel_id)
                frontier.append((neighbour, d + 1))
    return None


async def relationship_detail(db: AsyncSession, cipher: FieldCipher, rel: Relationship) -> dict[str, Any]:
    support = await _edge_sources(db, [rel.id])
    entities = await _entities(db, rel.investigation_id, [rel.from_entity_id, rel.to_entity_id])
    allowed, failed, _ = evaluate(rel, await _links(db, rel.id))
    history = (
        await db.execute(
            select(RelationshipStatusHistory)
            .where(RelationshipStatusHistory.relationship_id == rel.id)
            .order_by(RelationshipStatusHistory.created_at)
        )
    ).scalars()
    return {
        **_edge(rel, support.get(rel.id, [])),
        "from_entity": _node(cipher, entities[rel.from_entity_id]) if rel.from_entity_id in entities else None,
        "to_entity": _node(cipher, entities[rel.to_entity_id]) if rel.to_entity_id in entities else None,
        "allowed_transitions": list(allowed),
        "failed_preconditions": failed,
        "history": [
            {
                "from_status": h.from_status,
                "to_status": h.to_status,
                "actor_id": str(h.actor_id) if h.actor_id else None,
                "justification": cipher.open_optional(
                    h.justification, table="relationship_status_history", column="justification", row_id=h.id
                ),
                "evidence_ids": [str(e) for e in h.evidence_ids],
                "created_at": h.created_at,
            }
            for h in history
        ],
    }
