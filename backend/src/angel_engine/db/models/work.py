"""Notes, reports, report exports, AI interactions and AI proposals (row-level security)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, CheckConstraint, ForeignKey, Integer, LargeBinary, Text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import text

from angel_engine.db.base import (
    Base,
    InvestigationScoped,
    check_in,
    created_at_col,
    scoped_args,
    scoped_fk,
    updated_at_col,
    uuid_pk,
)

AI_TASKS = (
    "summarize",
    "compare",
    "contradictions",
    "gaps",
    "suggest_queries",
    "extract",
    "timeline",
    "draft_report",
    "check_conclusion",
    "chat",
    "vision_clues",
)
GROUNDING = ("grounded", "partial", "insufficient_evidence", "policy_refused", "provider_refused")


class Note(InvestigationScoped, Base):
    __tablename__ = "notes"
    __table_args__ = scoped_args(
        "notes",
        CheckConstraint(
            check_in("target_type", ("investigation", "image", "finding", "source", "entity", "evidence")),
            name="target_type",
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    target_type: Mapped[str] = mapped_column(Text, nullable=False)
    target_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), index=True)
    body: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)  # [E]
    body_tokens: Mapped[list[int]] = mapped_column(ARRAY(BigInteger), nullable=False, server_default=text("'{}'"))
    author_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()


class Report(InvestigationScoped, Base):
    __tablename__ = "reports"
    __table_args__ = scoped_args(
        "reports",
        CheckConstraint(check_in("status", ("draft", "final")), name="status"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    title: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)  # [E]
    status: Mapped[str] = mapped_column(Text, nullable=False, default="draft")
    options: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    body: Mapped[bytes | None] = mapped_column(LargeBinary)  # [E] ReportDocument JSON
    generated_at: Mapped[datetime | None]
    final_mac: Mapped[bytes | None] = mapped_column(LargeBinary)
    final_sha256: Mapped[str | None] = mapped_column(Text)
    audit_seq: Mapped[int | None] = mapped_column(BigInteger)
    finalized_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    finalized_at: Mapped[datetime | None]
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()

    __mapper_args__ = {"version_id_col": version, "eager_defaults": True}  # noqa: RUF012


class ReportExport(InvestigationScoped, Base):
    __tablename__ = "report_exports"
    __table_args__ = scoped_args(
        "report_exports",
        scoped_fk("report_id", "reports"),
        CheckConstraint(check_in("format", ("html", "markdown", "json", "pdf")), name="format"),
        CheckConstraint(check_in("status", ("pending", "ready", "failed", "expired")), name="status"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    report_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    format: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="pending")
    object_key: Mapped[str | None] = mapped_column(Text)
    file_key: Mapped[bytes | None] = mapped_column(LargeBinary)  # [E]
    byte_size: Mapped[int | None] = mapped_column(Integer)
    sha256: Mapped[str | None] = mapped_column(Text)
    expires_at: Mapped[datetime]
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    downloaded_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = created_at_col()


class AIInteraction(InvestigationScoped, Base):
    __tablename__ = "ai_interactions"
    __table_args__ = scoped_args(
        "ai_interactions",
        CheckConstraint(check_in("task", AI_TASKS), name="task"),
        CheckConstraint(check_in("status", ("pending", "running", "completed", "failed")), name="status"),
        CheckConstraint(f"grounding IS NULL OR {check_in('grounding', GROUNDING)}", name="grounding"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    task: Mapped[str] = mapped_column(Text, nullable=False)
    prompt: Mapped[bytes | None] = mapped_column(LargeBinary)  # [E]
    response: Mapped[bytes | None] = mapped_column(LargeBinary)  # [E] validated segments JSON
    context_evidence_ids: Mapped[list[uuid.UUID]] = mapped_column(
        ARRAY(UUID(as_uuid=True)), nullable=False, server_default=text("'{}'")
    )
    cited_evidence_ids: Mapped[list[uuid.UUID]] = mapped_column(
        ARRAY(UUID(as_uuid=True)), nullable=False, server_default=text("'{}'")
    )
    provider: Mapped[str] = mapped_column(Text, nullable=False)
    model: Mapped[str | None] = mapped_column(Text)
    input_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="pending")
    grounding: Mapped[str | None] = mapped_column(Text)
    validation: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    policy_decision_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    error_code: Mapped[str | None] = mapped_column(Text)
    expires_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = created_at_col()
    completed_at: Mapped[datetime | None]


class AIProposal(InvestigationScoped, Base):
    """AI output awaiting a human decision. Accepted items are stored as AI hypotheses."""

    __tablename__ = "ai_proposals"
    __table_args__ = scoped_args(
        "ai_proposals",
        scoped_fk("interaction_id", "ai_interactions"),
        CheckConstraint(
            check_in("kind", ("entity", "relationship", "timeline_event", "finding", "query", "contradiction", "gap")),
            name="kind",
        ),
        CheckConstraint(check_in("status", ("pending", "accepted", "rejected")), name="status"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    interaction_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)  # [E] JSON
    evidence_ids: Mapped[list[uuid.UUID]] = mapped_column(
        ARRAY(UUID(as_uuid=True)), nullable=False, server_default=text("'{}'")
    )
    status: Mapped[str] = mapped_column(Text, nullable=False, default="pending")
    decided_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    decided_at: Mapped[datetime | None]
    result_ref: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    created_at: Mapped[datetime] = created_at_col()
