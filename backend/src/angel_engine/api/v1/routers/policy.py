"""Acceptable-use policy: preflight checks for forms (e.g. the New Investigation wizard)."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from angel_engine.api.deps import CurrentPrincipal, DbSession
from angel_engine.core.enums import SubjectType
from angel_engine.policy.types import PolicyContext, Surface
from angel_engine.policy_gate import preflight

router = APIRouter(prefix="/policy", tags=["policy"])


class PreflightIn(BaseModel):
    text: str = Field(min_length=1, max_length=8000)
    surface: Literal[
        "investigation_purpose", "collection_query", "assistant_prompt", "note", "image_note", "report_section"
    ] = "investigation_purpose"
    subject_type: SubjectType | None = None


class AlternativeOut(BaseModel):
    kind: str
    label: str
    template: str | None = None
    connector_id: str | None = None


class PreflightOut(BaseModel):
    decision: str
    categories: list[str]
    notices: list[str]
    rationale: str
    alternatives: list[AlternativeOut]
    requires_acknowledgement: bool
    requires_review: bool


@router.post("/preflight")
async def policy_preflight(body: PreflightIn, principal: CurrentPrincipal, db: DbSession) -> PreflightOut:
    """Check text against the Acceptable Use Policy before submitting it.

    Allowed/warned/review results are not stored; refusals are recorded (and raise ``policy-refused``)
    exactly as they would be on submission.
    """
    subject = body.subject_type.value if body.subject_type else None
    ctx = PolicyContext(
        surface=Surface(body.surface), subject_type=subject, restricted_mode=subject == SubjectType.INDIVIDUAL.value
    )
    result = await preflight(principal.services, db, principal.user, body.text, ctx, actor_event=principal.event(""))
    return PreflightOut(
        decision=result.decision.value,
        categories=[c.value for c in result.categories],
        notices=list(result.notices),
        rationale=result.rationale,
        alternatives=[
            AlternativeOut(kind=a.kind, label=a.label, template=a.template, connector_id=a.connector_id)
            for a in result.alternatives
        ],
        requires_acknowledgement=result.decision.value == "warn",
        requires_review=result.decision.value == "review" or subject == SubjectType.INDIVIDUAL.value,
    )
