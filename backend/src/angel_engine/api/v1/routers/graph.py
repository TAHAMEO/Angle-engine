"""Entities, relationships and the evidence graph (every edge shows its supporting sources)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select

from angel_engine.api.v1.routers._common import (
    Keyset,
    Page,
    ReadCtx,
    VerifyCtx,
    WriteCtx,
    contains_pattern,
    get_scoped,
)
from angel_engine.core.enums import EntityType, RelationshipType, VerificationStatus
from angel_engine.core.problems import NotFound
from angel_engine.db.models import Entity, EntityMention, EvidenceItem, Relationship
from angel_engine.entities.service import EntityInput, entity_view, merge_entities, upsert_entity
from angel_engine.graph import service as graph
from angel_engine.graph.service import RelationshipInput

router = APIRouter(tags=["graph"])
BASE = "/investigations/{investigation_id}"


class EntityOut(BaseModel):
    id: str
    type: str
    name: str
    location_level: str | None
    country: str | None
    public_role_basis: str | None
    attributes: dict[str, Any]
    merged_into_id: str | None
    created_via: str
    created_at: datetime
    relationship_count: int = 0
    mention_count: int = 0


class EntityDetail(EntityOut):
    relationships: list[dict[str, Any]]
    mentions: list[dict[str, str]]


class EntityCreate(BaseModel):
    type: EntityType
    name: str = Field(min_length=1, max_length=300)
    location_level: Literal["country", "admin1", "locality", "landmark"] | None = None
    country: str | None = Field(default=None, pattern=r"^[A-Z]{2}$")
    public_role_basis: str | None = Field(default=None, max_length=1000)
    attributes: dict[str, str] = Field(default_factory=dict, max_length=20)
    evidence_ids: list[uuid.UUID] = Field(default_factory=list, max_length=50)


class MergeIn(BaseModel):
    into_entity_id: uuid.UUID


class RelationshipCreate(BaseModel):
    from_entity_id: uuid.UUID
    rel_type: RelationshipType
    to_entity_id: uuid.UUID
    evidence_ids: list[uuid.UUID] = Field(min_length=1, max_length=50)
    stance: Literal["supports", "contradicts", "context"] = "supports"


class RelationshipEvidenceIn(BaseModel):
    evidence_ids: list[uuid.UUID] = Field(min_length=1, max_length=50)
    stance: Literal["supports", "contradicts", "context"] = "supports"


class RelationshipTransitionIn(BaseModel):
    to_status: VerificationStatus
    justification: str = Field(min_length=20, max_length=4000)
    evidence_ids: list[uuid.UUID] = Field(default_factory=list, max_length=50)
    independence_attested: bool = False


class GraphOut(BaseModel):
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    truncated: bool


class PathOut(BaseModel):
    found: bool
    relationship_ids: list[str]
    edges: list[dict[str, Any]]


# --------------------------------------------------------------------------------------------------
# Entities
# --------------------------------------------------------------------------------------------------
@router.get(BASE + "/entities")
async def list_entities(
    ctx: ReadCtx,
    type: Annotated[list[EntityType] | None, Query()] = None,
    q: Annotated[str | None, Query(max_length=100)] = None,
    limit: Annotated[int | None, Query(ge=1, le=100)] = None,
    cursor: Annotated[str | None, Query(max_length=600)] = None,
) -> Page[EntityOut]:
    keyset = Keyset(ctx, {"type": sorted(t.value for t in type or []), "q": q}, limit, cursor)
    stmt = select(Entity).where(Entity.investigation_id == ctx.id, Entity.merged_into_id.is_(None))
    if type:
        stmt = stmt.where(Entity.type.in_([t.value for t in type]))
    if q:
        # Only intrinsically public names are stored in plaintext and searchable by substring.
        stmt = stmt.where(Entity.name.ilike(contains_pattern(q), escape="\\"))
    rows = list((await ctx.db.execute(keyset.apply(stmt, Entity.created_at, Entity.id))).scalars())
    rows, next_cursor = keyset.page(rows, lambda e: (e.created_at, e.id))
    cipher = await ctx.cipher()
    ids = [e.id for e in rows]
    rel_counts: dict[uuid.UUID, int] = {}
    mention_counts: dict[uuid.UUID, int] = {}
    if ids:
        for column in (Relationship.from_entity_id, Relationship.to_entity_id):
            for entity_id, n in (
                await ctx.db.execute(select(column, func.count()).where(column.in_(ids)).group_by(column))
            ).all():
                rel_counts[entity_id] = rel_counts.get(entity_id, 0) + int(n)
        mention_counts = {
            entity_id: int(n)
            for entity_id, n in (
                await ctx.db.execute(
                    select(EntityMention.entity_id, func.count())
                    .where(EntityMention.entity_id.in_(ids))
                    .group_by(EntityMention.entity_id)
                )
            ).all()
        }
    items = [
        EntityOut(
            **entity_view(cipher, e),
            relationship_count=rel_counts.get(e.id, 0),
            mention_count=mention_counts.get(e.id, 0),
        )
        for e in rows
    ]
    return Page(items=items, next_cursor=next_cursor, has_more=next_cursor is not None)


@router.post(BASE + "/entities", status_code=201)
async def create_entity(body: EntityCreate, ctx: WriteCtx) -> EntityOut:
    cipher = await ctx.cipher()
    entity, created = await upsert_entity(
        ctx.db,
        cipher,
        ctx.investigation,
        EntityInput(
            type=body.type.value,
            name=body.name,
            attributes=dict(body.attributes),
            location_level=body.location_level,
            country=body.country,
            public_role_basis=body.public_role_basis,
            created_via="manual",
        ),
    )
    if body.evidence_ids:
        from angel_engine.entities.service import add_mention

        found = set(
            (
                await ctx.db.execute(
                    select(EvidenceItem.id).where(
                        EvidenceItem.investigation_id == ctx.id, EvidenceItem.id.in_(body.evidence_ids)
                    )
                )
            ).scalars()
        )
        for evidence_id in body.evidence_ids:
            if evidence_id in found:
                await add_mention(ctx.db, ctx.investigation, entity.id, evidence_id)
    ctx.audit(
        "entity.created" if created else "entity.reused",
        target_type="entity",
        target_id=str(entity.id),
        details={"type": entity.type},
    )
    return EntityOut(**entity_view(cipher, entity))


@router.get(BASE + "/entities/{entity_id}")
async def get_entity(entity_id: uuid.UUID, ctx: ReadCtx) -> EntityDetail:
    entity = await get_scoped(ctx.db, Entity, ctx, entity_id)
    cipher = await ctx.cipher()
    rels = (
        (
            await ctx.db.execute(
                select(Relationship).where(
                    or_(Relationship.from_entity_id == entity.id, Relationship.to_entity_id == entity.id)
                )
            )
        )
        .scalars()
        .all()
    )
    mentions = (
        await ctx.db.execute(
            select(EvidenceItem.id, EvidenceItem.label_seq)
            .join(EntityMention, EntityMention.evidence_id == EvidenceItem.id)
            .where(EntityMention.entity_id == entity.id)
            .order_by(EvidenceItem.label_seq)
        )
    ).all()
    return EntityDetail(
        **entity_view(cipher, entity),
        relationship_count=len(rels),
        mention_count=len(mentions),
        relationships=[await graph.relationship_detail(ctx.db, cipher, r) for r in rels[:100]],
        mentions=[{"evidence_id": str(i), "label": f"E-{seq}"} for i, seq in mentions],
    )


@router.post(BASE + "/entities/{entity_id}/merge")
async def merge_entity(entity_id: uuid.UUID, body: MergeIn, ctx: WriteCtx) -> EntityOut:
    source = await get_scoped(ctx.db, Entity, ctx, entity_id)
    target = await get_scoped(ctx.db, Entity, ctx, body.into_entity_id)
    moved = await merge_entities(ctx.db, ctx.investigation, source, target)
    ctx.audit(
        "entity.merged",
        target_type="entity",
        target_id=str(source.id),
        details={"into": str(target.id), "relationships_moved": moved},
    )
    return EntityOut(**entity_view(await ctx.cipher(), target))


# --------------------------------------------------------------------------------------------------
# Relationships
# --------------------------------------------------------------------------------------------------
@router.get(BASE + "/relationships")
async def list_relationships(
    ctx: ReadCtx,
    status: Annotated[list[VerificationStatus] | None, Query()] = None,
    rel_type: Annotated[list[RelationshipType] | None, Query()] = None,
    entity_id: uuid.UUID | None = None,
) -> list[dict[str, Any]]:
    stmt = select(Relationship).where(Relationship.investigation_id == ctx.id).order_by(Relationship.created_at)
    if status:
        stmt = stmt.where(Relationship.verification_status.in_([s.value for s in status]))
    if rel_type:
        stmt = stmt.where(Relationship.rel_type.in_([t.value for t in rel_type]))
    if entity_id:
        stmt = stmt.where(or_(Relationship.from_entity_id == entity_id, Relationship.to_entity_id == entity_id))
    cipher = await ctx.cipher()
    rows = (await ctx.db.execute(stmt.limit(500))).scalars().all()
    return [await graph.relationship_detail(ctx.db, cipher, r) for r in rows]


@router.post(BASE + "/relationships", status_code=201)
async def create_relationship(body: RelationshipCreate, ctx: WriteCtx) -> dict[str, Any]:
    rel, created = await graph.upsert_relationship(
        ctx.db,
        ctx.investigation,
        RelationshipInput(
            from_entity_id=body.from_entity_id,
            rel_type=body.rel_type.value,
            to_entity_id=body.to_entity_id,
            evidence_ids=tuple(body.evidence_ids),
            stance=body.stance,
            provenance="analyst_inference",
            created_via="manual",
            created_by=ctx.principal.user_id,
        ),
    )
    ctx.audit(
        "relationship.created" if created else "relationship.evidence_added",
        target_type="relationship",
        target_id=str(rel.id),
        details={"rel_type": rel.rel_type, "evidence": len(body.evidence_ids)},
    )
    return await graph.relationship_detail(ctx.db, await ctx.cipher(), rel)


@router.get(BASE + "/relationships/{relationship_id}")
async def get_relationship(relationship_id: uuid.UUID, ctx: ReadCtx) -> dict[str, Any]:
    rel = await get_scoped(ctx.db, Relationship, ctx, relationship_id)
    return await graph.relationship_detail(ctx.db, await ctx.cipher(), rel)


@router.post(BASE + "/relationships/{relationship_id}/evidence")
async def add_relationship_evidence(
    relationship_id: uuid.UUID, body: RelationshipEvidenceIn, ctx: WriteCtx
) -> dict[str, Any]:
    rel = await get_scoped(ctx.db, Relationship, ctx, relationship_id)
    added = await graph.link_evidence(ctx.db, ctx.investigation, rel, body.evidence_ids, body.stance)
    await graph.recheck(ctx.db, rel)
    ctx.audit(
        "relationship.evidence_added",
        target_type="relationship",
        target_id=str(rel.id),
        details={"added": added, "stance": body.stance},
    )
    return await graph.relationship_detail(ctx.db, await ctx.cipher(), rel)


@router.delete(BASE + "/relationships/{relationship_id}/evidence/{evidence_id}")
async def remove_relationship_evidence(
    relationship_id: uuid.UUID, evidence_id: uuid.UUID, ctx: WriteCtx
) -> dict[str, Any]:
    rel = await get_scoped(ctx.db, Relationship, ctx, relationship_id)
    removed = await graph.unlink_evidence(ctx.db, rel, evidence_id)
    ctx.audit(
        "relationship.evidence_removed",
        target_type="relationship",
        target_id=str(relationship_id),
        details={"relationship_removed": removed},
    )
    if removed:
        return {"status": "relationship_removed"}
    return await graph.relationship_detail(ctx.db, await ctx.cipher(), rel)


@router.post(BASE + "/relationships/{relationship_id}/transitions")
async def relationship_transition(
    relationship_id: uuid.UUID, body: RelationshipTransitionIn, ctx: VerifyCtx
) -> dict[str, Any]:
    rel = await get_scoped(ctx.db, Relationship, ctx, relationship_id)
    cipher = await ctx.cipher()
    previous = await graph.transition(
        ctx.db,
        cipher,
        rel,
        body.to_status.value,
        body.justification,
        body.evidence_ids,
        actor_id=ctx.principal.user_id,
        independence_attested=body.independence_attested,
    )
    ctx.audit(
        "relationship.status_changed",
        target_type="relationship",
        target_id=str(rel.id),
        details={"from": previous, "to": body.to_status.value},
    )
    return await graph.relationship_detail(ctx.db, cipher, rel)


# --------------------------------------------------------------------------------------------------
# Graph queries
# --------------------------------------------------------------------------------------------------
@router.get(BASE + "/graph")
async def get_graph(
    ctx: ReadCtx,
    root: uuid.UUID | None = None,
    depth: Annotated[int, Query(ge=1, le=3)] = 2,
    status: Annotated[list[VerificationStatus] | None, Query()] = None,
    rel_type: Annotated[list[RelationshipType] | None, Query()] = None,
    entity_type: Annotated[list[EntityType] | None, Query()] = None,
) -> GraphOut:
    data = await graph.subgraph(
        ctx.db,
        await ctx.cipher(),
        ctx.investigation,
        root=root,
        depth=depth,
        statuses=[s.value for s in status] if status else None,
        rel_types=[t.value for t in rel_type] if rel_type else None,
        entity_types=[t.value for t in entity_type] if entity_type else None,
    )
    return GraphOut(**data)


@router.get(BASE + "/graph/path")
async def get_path(
    ctx: ReadCtx,
    from_entity: Annotated[uuid.UUID, Query(alias="from")],
    to_entity: Annotated[uuid.UUID, Query(alias="to")],
) -> PathOut:
    for entity_id in (from_entity, to_entity):
        if (
            await ctx.db.execute(select(Entity.id).where(Entity.id == entity_id, Entity.investigation_id == ctx.id))
        ).first() is None:
            raise NotFound()
    path = await graph.shortest_path(ctx.db, ctx.investigation, from_entity, to_entity)
    if path is None:
        return PathOut(found=False, relationship_ids=[], edges=[])
    cipher = await ctx.cipher()
    rels = {r.id: r for r in (await ctx.db.execute(select(Relationship).where(Relationship.id.in_(path)))).scalars()}
    return PathOut(
        found=True,
        relationship_ids=[str(p) for p in path],
        edges=[await graph.relationship_detail(ctx.db, cipher, rels[p]) for p in path if p in rels],
    )
