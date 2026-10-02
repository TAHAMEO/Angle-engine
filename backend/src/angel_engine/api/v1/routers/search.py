"""Keyword search over encrypted content (blind tokens), within one investigation or across memberships.

Search is exact (stemmed) term AND-matching: the database only stores keyed term tokens, never the
plaintext. Entity names of intrinsically public types also match by substring.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Query
from pydantic import BaseModel
from sqlalchemy import select

from angel_engine.api.deps import CurrentPrincipal, DbSession
from angel_engine.api.v1.routers._common import ReadCtx, contains_pattern, snippet
from angel_engine.core.enums import InvestigationStatus
from angel_engine.crypto.blind_index import query_tokens
from angel_engine.crypto.envelope import FieldCipher, KeyDestroyedError
from angel_engine.db.models import (
    Entity,
    EvidenceItem,
    Finding,
    Investigation,
    InvestigationMember,
    Note,
    Source,
)
from angel_engine.db.session import set_investigation_scope
from angel_engine.entities.service import entity_name

router = APIRouter(tags=["search"])
PER_TYPE = 10
MAX_INVESTIGATIONS = 50


class Hit(BaseModel):
    id: str
    label: str | None = None
    kind: str
    text: str | None
    status: str | None = None
    provenance: str | None = None
    host: str | None = None


class SearchOut(BaseModel):
    query: str
    terms: int
    findings: list[Hit]
    evidence: list[Hit]
    sources: list[Hit]
    entities: list[Hit]
    notes: list[Hit]


class InvestigationHits(BaseModel):
    investigation_id: str
    ref: str
    title: str
    findings: list[Hit]
    evidence: list[Hit]


async def _search_one(db: Any, cipher: FieldCipher, inv_id: uuid.UUID, q: str, limit: int) -> dict[str, list[Hit]]:
    wanted = query_tokens(cipher, q)
    out: dict[str, list[Hit]] = {"findings": [], "evidence": [], "sources": [], "entities": [], "notes": []}
    if wanted:
        for f in (
            await db.execute(
                select(Finding)
                .where(Finding.investigation_id == inv_id, Finding.statement_tokens.contains(wanted))
                .order_by(Finding.updated_at.desc())
                .limit(limit)
            )
        ).scalars():
            out["findings"].append(
                Hit(
                    id=str(f.id),
                    label=f"F-{f.label_seq}",
                    kind="finding",
                    status=f.verification_status,
                    provenance=f.provenance,
                    text=snippet(cipher.open(f.statement, table="findings", column="statement", row_id=f.id), 200),
                )
            )
        rows = (
            await db.execute(
                select(EvidenceItem, Source.host)
                .outerjoin(Source, Source.id == EvidenceItem.source_id)
                .where(EvidenceItem.investigation_id == inv_id, EvidenceItem.search_tokens.contains(wanted))
                .order_by(EvidenceItem.captured_at.desc())
                .limit(limit)
            )
        ).all()
        for ev, host in rows:
            hidden = bool(ev.sensitivity_flags)
            text = None if hidden else cipher.open(ev.excerpt, table="evidence_items", column="excerpt", row_id=ev.id)
            out["evidence"].append(
                Hit(
                    id=str(ev.id),
                    label=f"E-{ev.label_seq}",
                    kind=ev.evidence_type,
                    provenance=ev.provenance,
                    host=host,
                    text=snippet(text, 200),
                )
            )
        for s in (
            await db.execute(
                select(Source)
                .where(Source.investigation_id == inv_id, Source.title_tokens.contains(wanted))
                .order_by(Source.last_captured_at.desc())
                .limit(limit)
            )
        ).scalars():
            out["sources"].append(
                Hit(
                    id=str(s.id),
                    label=f"S-{s.label_seq}",
                    kind=s.source_category,
                    host=s.host,
                    text=cipher.open_optional(s.title, table="sources", column="title", row_id=s.id),
                )
            )
        for n in (
            await db.execute(
                select(Note)
                .where(Note.investigation_id == inv_id, Note.body_tokens.contains(wanted))
                .order_by(Note.updated_at.desc())
                .limit(limit)
            )
        ).scalars():
            out["notes"].append(
                Hit(
                    id=str(n.id),
                    kind=n.target_type,
                    text=snippet(cipher.open(n.body, table="notes", column="body", row_id=n.id), 200),
                )
            )
    for e in (
        await db.execute(
            select(Entity)
            .where(
                Entity.investigation_id == inv_id,
                Entity.merged_into_id.is_(None),
                Entity.name.ilike(contains_pattern(q), escape="\\"),
            )
            .limit(limit)
        )
    ).scalars():
        out["entities"].append(Hit(id=str(e.id), kind=e.type, text=entity_name(cipher, e)))
    return out


@router.get("/investigations/{investigation_id}/search")
async def search_investigation(
    ctx: ReadCtx,
    q: Annotated[str, Query(min_length=2, max_length=200)],
    limit: Annotated[int, Query(ge=1, le=50)] = PER_TYPE,
) -> SearchOut:
    cipher = await ctx.cipher()
    hits = await _search_one(ctx.db, cipher, ctx.id, q, limit)
    return SearchOut(query=q, terms=len(query_tokens(cipher, q)), **hits)


@router.get("/search")
async def search_everywhere(
    principal: CurrentPrincipal,
    db: DbSession,
    q: Annotated[str, Query(min_length=2, max_length=200)],
) -> list[InvestigationHits]:
    """Search every investigation the user is a member of (never oversight-only or other teams' work)."""
    rows = (
        (
            await db.execute(
                select(Investigation)
                .join(InvestigationMember, InvestigationMember.investigation_id == Investigation.id)
                .where(
                    InvestigationMember.user_id == principal.user_id,
                    Investigation.status != InvestigationStatus.DELETED.value,
                )
                .order_by(Investigation.updated_at.desc())
                .limit(MAX_INVESTIGATIONS)
            )
        )
        .scalars()
        .all()
    )
    await set_investigation_scope(db, [inv.id for inv in rows])
    out: list[InvestigationHits] = []
    for inv in rows:
        try:
            cipher = await principal.services.vault.investigation_cipher(db, inv.id)
        except KeyDestroyedError:
            continue
        hits = await _search_one(db, cipher, inv.id, q, 5)
        if hits["findings"] or hits["evidence"]:
            out.append(
                InvestigationHits(
                    investigation_id=str(inv.id),
                    ref=inv.public_ref,
                    title=inv.title,
                    findings=hits["findings"],
                    evidence=hits["evidence"],
                )
            )
    return out
