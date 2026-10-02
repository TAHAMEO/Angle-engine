"""SQLAlchemy declarative base, naming conventions and shared column helpers."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, ForeignKeyConstraint, MetaData, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, declared_attr, mapped_column

from angel_engine.core.ids import new_id

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)
    type_annotation_map = {  # noqa: RUF012
        dict[str, Any]: JSONB,
        list[int]: ARRAY(BigInteger),
        datetime: DateTime(timezone=True),
    }


def uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(primary_key=True, default=new_id)


def created_at_col() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


def updated_at_col() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


def check_in(column: str, values: tuple[str, ...] | list[str]) -> str:
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"{column} IN ({quoted})"


class InvestigationScoped:
    """Mixin for row-level-security protected tables.

    Adds ``investigation_id`` and the ``UNIQUE(investigation_id, id)`` target that child tables use for
    composite foreign keys, so rows can never be linked across investigations.
    """

    @declared_attr
    def investigation_id(cls) -> Mapped[uuid.UUID]:
        return mapped_column(index=True, nullable=False)


def scoped_args(table: str, *extra: Any) -> tuple[Any, ...]:
    """``__table_args__`` for an investigation-scoped table (adds the FK and composite-key target)."""
    return (
        ForeignKeyConstraint(
            ["investigation_id"], ["investigations.id"], ondelete="CASCADE", name=f"fk_{table}_investigation"
        ),
        UniqueConstraint("investigation_id", "id", name=f"uq_{table}_inv_id"),
        *extra,
    )


def scoped_fk(
    column: str, target_table: str, *, ondelete: str = "CASCADE", name: str | None = None
) -> ForeignKeyConstraint:
    """Composite FK ``(investigation_id, column) -> target(investigation_id, id)``.

    ``ondelete="SET NULL"`` nulls only the referencing column (PostgreSQL 15+ column-list syntax),
    never ``investigation_id``.
    """
    action = f"SET NULL ({column})" if ondelete == "SET NULL" else ondelete
    return ForeignKeyConstraint(
        ["investigation_id", column],
        [f"{target_table}.investigation_id", f"{target_table}.id"],
        ondelete=action,
        name=name or f"fk_{column}_{target_table}",
    )
