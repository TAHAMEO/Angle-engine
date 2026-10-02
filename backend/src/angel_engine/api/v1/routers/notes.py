"""Investigator notes on an investigation, image, finding, source, entity or evidence item.

Notes are screened by the acceptable-use policy (image notes included) and redacted by the
sensitive-data guard before they are encrypted and indexed.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field
from sqlalchemy import select

from angel_engine.api.deps import InvCtx
from angel_engine.api.v1.routers._common import ReadCtx, WriteCtx, get_scoped
from angel_engine.core.enums import MemberRole
from angel_engine.core.ids import new_id
from angel_engine.core.problems import Forbidden, ValidationProblem
from angel_engine.crypto.blind_index import tokens
from angel_engine.db.models import (
    Entity,
    EvidenceItem,
    Finding,
    Image,
    Note,
    Source,
    User,
)
from angel_engine.evidence.service import redaction_mode
from angel_engine.guard import RedactionContext, SourceKind, redact_text
from angel_engine.policy.types import PolicyContext, Surface
from angel_engine.policy_gate import screen

router = APIRouter(tags=["notes"])
BASE = "/investigations/{investigation_id}/notes"
TARGETS = {"image": Image, "finding": Finding, "source": Source, "entity": Entity, "evidence": EvidenceItem}
TargetType = Literal["investigation", "image", "finding", "source", "entity", "evidence"]


class NoteOut(BaseModel):
    id: str
    target_type: str
    target_id: str | None
    body: str
    author_name: str | None
    is_author: bool
    redaction_counts: dict[str, int] = {}
    created_at: datetime
    updated_at: datetime


class NoteIn(BaseModel):
    target_type: TargetType = "investigation"
    target_id: uuid.UUID | None = None
    body: str = Field(min_length=1, max_length=10000)


class NotePatch(BaseModel):
    body: str = Field(min_length=1, max_length=10000)


async def _prepare(ctx: InvCtx, target_type: str, target_id: uuid.UUID | None, body: str) -> tuple[str, dict[str, int]]:
    face_count = 0
    if target_type == "investigation":
        if target_id is not None:
            raise ValidationProblem("Investigation notes do not take a target id.", code="invalid_target")
    else:
        if target_id is None:
            raise ValidationProblem("Choose what the note is about.", code="target_required")
        row = await get_scoped(ctx.db, TARGETS[target_type], ctx, target_id)
        if target_type == "image":
            face_count = row.face_count
    surface = Surface.IMAGE_NOTE if target_type == "image" else Surface.NOTE
    await screen(
        ctx.principal.services,
        ctx.db,
        ctx.principal.user,
        body,
        PolicyContext(
            surface=surface,
            subject_type=ctx.investigation.subject_type,
            restricted_mode=ctx.investigation.restricted_mode,
            face_count=face_count,
        ),
        investigation_id=ctx.id,
        target_type="note",
        actor_event=ctx.principal.event(""),
    )
    red = redact_text(
        body, mode=redaction_mode(ctx.investigation), context=RedactionContext(source_kind=SourceKind.USER_NOTE)
    )
    if not red.text.strip():
        raise ValidationProblem("The note is empty after redaction.", code="empty_note")
    return red.text, dict(red.counts)


async def _out(ctx: InvCtx, notes: list[Note]) -> list[NoteOut]:
    cipher = await ctx.cipher()
    authors = {n.author_id for n in notes if n.author_id}
    names = (
        dict((await ctx.db.execute(select(User.id, User.display_name).where(User.id.in_(authors)))).all())
        if authors
        else {}
    )
    return [
        NoteOut(
            id=str(n.id),
            target_type=n.target_type,
            target_id=str(n.target_id) if n.target_id else None,
            body=cipher.open(n.body, table="notes", column="body", row_id=n.id),
            author_name=names.get(n.author_id) if n.author_id else None,
            is_author=n.author_id == ctx.principal.user_id,
            created_at=n.created_at,
            updated_at=n.updated_at,
        )
        for n in notes
    ]


@router.get(BASE)
async def list_notes(
    ctx: ReadCtx, target_type: TargetType | None = None, target_id: uuid.UUID | None = None
) -> list[NoteOut]:
    stmt = select(Note).where(Note.investigation_id == ctx.id)
    if target_type:
        stmt = stmt.where(Note.target_type == target_type)
    if target_id:
        stmt = stmt.where(Note.target_id == target_id)
    notes = list((await ctx.db.execute(stmt.order_by(Note.created_at.desc()).limit(500))).scalars())
    return await _out(ctx, notes)


@router.post(BASE, status_code=201)
async def create_note(body: NoteIn, ctx: WriteCtx) -> NoteOut:
    text_value, counts = await _prepare(ctx, body.target_type, body.target_id, body.body)
    cipher = await ctx.cipher()
    nid = new_id()
    note = Note(
        id=nid,
        investigation_id=ctx.id,
        target_type=body.target_type,
        target_id=body.target_id,
        body=cipher.seal(text_value, table="notes", column="body", row_id=nid),
        body_tokens=tokens(cipher, text_value),
        author_id=ctx.principal.user_id,
    )
    ctx.db.add(note)
    await ctx.db.flush()
    ctx.audit(
        "note.created",
        target_type="note",
        target_id=str(nid),
        details={"target_type": body.target_type, "redactions": counts},
    )
    out = (await _out(ctx, [note]))[0]
    out.redaction_counts = counts
    return out


@router.patch(BASE + "/{note_id}")
async def update_note(note_id: uuid.UUID, body: NotePatch, ctx: WriteCtx) -> NoteOut:
    note = await get_scoped(ctx.db, Note, ctx, note_id)
    if note.author_id != ctx.principal.user_id:
        raise Forbidden("Only the author can edit a note.", code="author_only")
    text_value, counts = await _prepare(ctx, note.target_type, note.target_id, body.body)
    cipher = await ctx.cipher()
    note.body = cipher.seal(text_value, table="notes", column="body", row_id=note.id)
    note.body_tokens = tokens(cipher, text_value)
    await ctx.db.flush()
    ctx.audit("note.updated", target_type="note", target_id=str(note.id), details={"redactions": counts})
    out = (await _out(ctx, [note]))[0]
    out.redaction_counts = counts
    return out


@router.delete(BASE + "/{note_id}")
async def delete_note(note_id: uuid.UUID, ctx: WriteCtx) -> dict[str, str]:
    note = await get_scoped(ctx.db, Note, ctx, note_id)
    if note.author_id != ctx.principal.user_id and ctx.membership != MemberRole.OWNER.value:
        raise Forbidden("Only the author or the investigation owner can delete a note.", code="author_only")
    await ctx.db.delete(note)
    await ctx.db.flush()
    ctx.audit("note.deleted", target_type="note", target_id=str(note_id))
    return {"status": "deleted"}
