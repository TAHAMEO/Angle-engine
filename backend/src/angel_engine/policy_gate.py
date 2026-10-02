"""Applies the acceptable-use policy engine to user-supplied text and records every decision.

Refusals are persisted in their own transaction (they must survive the failed request), update the
user's refusal flags (3 refusals in 7 days ⇒ supervisors notified, 5 ⇒ every request needs review,
repeated hard refusals ⇒ suspension pending admin review) and raise a problem+json response that
carries lawful alternatives.
"""

from __future__ import annotations

import uuid
from dataclasses import replace
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from angel_engine.app_state import Services
from angel_engine.audit.chain import AuditEvent, append_now
from angel_engine.core.clock import utcnow
from angel_engine.core.ids import new_id
from angel_engine.core.problems import PolicyAcknowledgementRequired, PolicyRefused, ServiceUnavailable
from angel_engine.crypto.keyed_hash import system_mac
from angel_engine.db.models import PolicyDecision, User
from angel_engine.policy.types import Decision, PolicyContext, PolicyResult

FLAG_WINDOW = timedelta(days=7)


def refusal_payload(decision_id: uuid.UUID, result: PolicyResult) -> dict[str, Any]:
    return {
        "decision_id": str(decision_id),
        "decision": result.decision.value,
        "categories": [c.value for c in result.categories],
        "rule_ids": list(result.rule_ids),
        "rule_pack_version": result.rule_pack_version,
        "rationale": result.rationale,
        "alternatives": [
            {
                k: v
                for k, v in {
                    "kind": a.kind,
                    "label": a.label,
                    "template": a.template,
                    "connector_id": a.connector_id,
                }.items()
                if v is not None
            }
            for a in result.alternatives
        ],
        "notices": list(result.notices),
    }


def decision_summary(row_id: uuid.UUID, result: PolicyResult) -> dict[str, Any]:
    return {
        "decision_id": str(row_id),
        "decision": result.decision.value,
        "categories": [c.value for c in result.categories],
        "notices": list(result.notices),
        "rationale": result.rationale,
    }


def require_acknowledgement(result: PolicyResult, acknowledged: bool) -> None:
    """``warn`` results proceed only after the user has seen and acknowledged the notices."""
    if result.decision == Decision.WARN and not acknowledged:
        raise PolicyAcknowledgementRequired(
            "Review the policy notices and confirm to continue.",
            policy={
                "decision": result.decision.value,
                "categories": [c.value for c in result.categories],
                "notices": list(result.notices),
                "rationale": result.rationale,
            },
        )


async def _build_row(
    svc: Services,
    db: AsyncSession,
    user: User,
    text: str,
    ctx: PolicyContext,
    result: PolicyResult,
    *,
    investigation_id: uuid.UUID | None,
    target_type: str | None,
    target_id: uuid.UUID | None,
) -> PolicyDecision:
    row_id = new_id()
    cipher = await svc.vault.system_cipher(db, "system_policy")
    return PolicyDecision(
        id=row_id,
        investigation_id=investigation_id,
        user_id=user.id,
        surface=ctx.surface.value,
        input=cipher.seal(text, table="policy_decisions", column="input", row_id=row_id),
        input_mac=system_mac(svc.keys.secret("audit"), "policy-input", text.casefold().strip()),
        decision=result.decision.value,
        categories=[c.value for c in result.categories],
        rule_ids=list(result.rule_ids),
        rule_pack_version=result.rule_pack_version or "unknown",
        llm_decision=result.llm_decision.value if result.llm_decision else None,
        rationale=result.rationale[:2000],
        target_type=target_type,
        target_id=target_id,
        input_expires_at=utcnow() + timedelta(days=svc.settings.policy_text_retention_days),
    )


async def _update_flags(db: AsyncSession, user_id: uuid.UUID) -> int:
    since = utcnow() - FLAG_WINDOW
    refusals = (
        await db.execute(
            select(func.count())
            .select_from(PolicyDecision)
            .where(
                PolicyDecision.user_id == user_id,
                PolicyDecision.decision == "refuse",
                PolicyDecision.created_at >= since,
            )
        )
    ).scalar_one()
    level = 0
    if refusals >= 3:
        level = 1
    if refusals >= 5:
        level = 2
    if refusals >= 8:
        level = 3
    user = (await db.execute(select(User).where(User.id == user_id).with_for_update())).scalar_one()
    user.refusal_flag_level = max(user.refusal_flag_level, level)
    return user.refusal_flag_level


async def _evaluate(svc: Services, user: User, text: str, ctx: PolicyContext) -> PolicyResult:
    engine = svc.get("policy")
    if engine is None:
        raise ServiceUnavailable("The acceptable-use policy engine is unavailable.", code="policy_unavailable")
    classifier = svc.get("policy_classifier") if svc.settings.policy_llm_classifier else None
    result: PolicyResult = await engine.evaluate_with_classifier(text, ctx, classifier)
    if user.refusal_flag_level >= 2 and result.decision in (Decision.ALLOW, Decision.WARN):
        result = replace(
            result,
            decision=Decision.REVIEW,
            notices=(*result.notices, "Requests from this account currently require supervisor review."),
        )
    return result


async def preflight(
    svc: Services, db: AsyncSession, user: User, text: str, ctx: PolicyContext, *, actor_event: AuditEvent | None = None
) -> PolicyResult:
    """Evaluate without recording (used while a form is being filled in). Refusals are still recorded."""
    result = await _evaluate(svc, user, text, ctx)
    if result.decision == Decision.REFUSE:
        await screen(svc, db, user, text, ctx, actor_event=actor_event)
    return result


async def screen(
    svc: Services,
    db: AsyncSession,
    user: User,
    text: str,
    ctx: PolicyContext,
    *,
    investigation_id: uuid.UUID | None = None,
    target_type: str | None = None,
    target_id: uuid.UUID | None = None,
    actor_event: AuditEvent | None = None,
) -> tuple[PolicyResult, PolicyDecision]:
    """Evaluate ``text``; record the decision; raise :class:`PolicyRefused` on refusal."""
    result = await _evaluate(svc, user, text, ctx)
    if result.decision == Decision.REFUSE:
        async with svc.db.session("app") as side:
            row = await _build_row(
                svc,
                side,
                user,
                text,
                ctx,
                result,
                investigation_id=investigation_id,
                target_type=target_type,
                target_id=target_id,
            )
            side.add(row)
            await side.flush()
            level = await _update_flags(side, user.id)
            base = actor_event or AuditEvent(action="", actor_id=user.id, actor_role=user.role)
            await append_now(
                side,
                svc.audit_key,
                [
                    replace(
                        base,
                        action="policy.refused",
                        outcome="denied",
                        investigation_id=investigation_id,
                        target_type="policy_decision",
                        target_id=str(row.id),
                        details={
                            "surface": ctx.surface.value,
                            "categories": [c.value for c in result.categories],
                            "rule_ids": list(result.rule_ids),
                            "flag_level": level,
                        },
                    )
                ],
            )
        raise PolicyRefused(
            result.rationale or "This request is not permitted by the Acceptable Use Policy.",
            policy=refusal_payload(row.id, result),
        )
    row = await _build_row(
        svc,
        db,
        user,
        text,
        ctx,
        result,
        investigation_id=investigation_id,
        target_type=target_type,
        target_id=target_id,
    )
    db.add(row)
    await db.flush()
    return result, row
