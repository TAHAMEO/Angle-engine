"""Shared helpers for investigation-scoped routers: dependencies, pagination, ETags and small views."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Generic, TypeVar

from fastapi import Depends, Header
from pydantic import BaseModel
from sqlalchemy import select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from angel_engine.api.deps import InvCtx, investigation_scope
from angel_engine.authz.permissions import Perm
from angel_engine.core.pagination import clamp_limit, filter_fingerprint
from angel_engine.core.problems import NotFound, PreconditionFailed, PreconditionRequired
from angel_engine.crypto.envelope import FieldCipher
from angel_engine.db.models import Source

T = TypeVar("T")

ReadCtx = Annotated[InvCtx, Depends(investigation_scope(Perm.CONTENT_READ))]
WriteCtx = Annotated[InvCtx, Depends(investigation_scope(Perm.CONTENT_WRITE))]
VerifyCtx = Annotated[InvCtx, Depends(investigation_scope(Perm.FINDING_VERIFY))]
IfMatch = Annotated[str | None, Header()]


class Page(BaseModel, Generic[T]):
    items: list[T]
    next_cursor: str | None = None
    has_more: bool = False


def require_version(if_match: str | None, current: int, *, required: bool = True) -> None:
    """Optimistic concurrency: compare an ``If-Match: "<version>"`` header with the row version."""
    if if_match is None:
        if required:
            raise PreconditionRequired(code="if_match_required", current_version=current)
        return
    if if_match.strip().removeprefix("W/").strip('"') != str(current):
        raise PreconditionFailed(code="version_mismatch", current_version=current)


async def get_scoped(db: AsyncSession, model: Any, ctx: InvCtx, object_id: uuid.UUID) -> Any:
    """Load a row of an investigation-scoped table, 404 when it belongs elsewhere (RLS also applies)."""
    row = (
        await db.execute(select(model).where(model.id == object_id, model.investigation_id == ctx.id))
    ).scalar_one_or_none()
    if row is None:
        raise NotFound()
    return row


class Keyset:
    """Descending keyset pagination on ``(timestamp column, id)`` with signed cursors."""

    def __init__(self, ctx: InvCtx, filters: dict[str, Any], limit: int | None, cursor: str | None) -> None:
        self.codec = ctx.principal.services.cursors
        self.fingerprint = filter_fingerprint({"inv": str(ctx.id), **filters})
        self.limit = clamp_limit(limit)
        self.position: tuple[datetime, uuid.UUID] | None = None
        if cursor:
            payload = self.codec.decode(cursor, filter_hash=self.fingerprint)
            self.position = (datetime.fromisoformat(payload["t"]), uuid.UUID(payload["i"]))

    def apply(self, stmt: Any, ts_col: Any, id_col: Any) -> Any:
        if self.position is not None:
            stmt = stmt.where(tuple_(ts_col, id_col) < tuple_(*self.position))
        return stmt.order_by(ts_col.desc(), id_col.desc()).limit(self.limit + 1)

    def page(self, rows: list[Any], key: Any) -> tuple[list[Any], str | None]:
        """Trim the look-ahead row and build the next cursor from ``key(row) -> (timestamp, id)``."""
        has_more = len(rows) > self.limit
        rows = rows[: self.limit]
        cursor = None
        if has_more and rows:
            ts, ident = key(rows[-1])
            cursor = self.codec.encode({"f": self.fingerprint, "t": ts.isoformat(), "i": str(ident)})
        return rows, cursor


class SourceMini(BaseModel):
    id: str
    label: str
    title: str | None
    host: str
    url: str
    category: str
    reliability: str | None
    access_status: str


def source_mini(cipher: FieldCipher, source: Source) -> SourceMini:
    return SourceMini(
        id=str(source.id),
        label=f"S-{source.label_seq}",
        title=cipher.open_optional(source.title, table="sources", column="title", row_id=source.id),
        host=source.host,
        url=cipher.open(source.url, table="sources", column="url", row_id=source.id),
        category=source.source_category,
        reliability=source.reliability,
        access_status=source.access_status,
    )


def contains_pattern(query: str) -> str:
    """A LIKE/ILIKE pattern matching ``query`` literally (use with ``escape="\\"``)."""
    escaped = query.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def snippet(text: str | None, limit: int = 280) -> str | None:
    if text is None or len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0]
    return cut + "…"
