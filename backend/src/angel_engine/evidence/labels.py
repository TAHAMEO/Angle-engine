"""Human-readable per-investigation labels: S-1 (source), E-1 (evidence), F-1 (finding), I-1 (image)."""

from __future__ import annotations

import uuid
from typing import Literal

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

Counter = Literal["source_seq", "evidence_seq", "finding_seq", "image_seq"]
PREFIX: dict[str, str] = {"source_seq": "S", "evidence_seq": "E", "finding_seq": "F", "image_seq": "I"}
_SQL = {
    counter: text(f"UPDATE investigations SET {counter} = {counter} + 1 WHERE id = :id RETURNING {counter}")  # noqa: S608
    for counter in PREFIX
}


async def next_label(db: AsyncSession, investigation_id: uuid.UUID, counter: Counter) -> int:
    """Allocate the next label number (serialized per investigation by the row lock)."""
    return int((await db.execute(_SQL[counter], {"id": investigation_id})).scalar_one())


def label(prefix: str, seq: int) -> str:
    return f"{prefix}-{seq}"


def source_label(seq: int) -> str:
    return label("S", seq)


def evidence_label(seq: int) -> str:
    return label("E", seq)


def finding_label(seq: int) -> str:
    return label("F", seq)


def image_label(seq: int) -> str:
    return label("I", seq)
