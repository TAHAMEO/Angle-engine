"""``ai.run`` (egress queue): build the evidence context, call the provider outside any transaction, validate the
answer and store it with its proposals. Transient provider failures retry; the last failure is recorded."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select

from angel_engine.ai import service
from angel_engine.ai.types import ProviderFailed, ProviderUnavailable
from angel_engine.app_state import Services
from angel_engine.audit.chain import AuditEvent, append_now
from angel_engine.core.clock import utcnow
from angel_engine.core.enums import InvestigationStatus
from angel_engine.crypto.envelope import FieldCipher, KeyDestroyedError
from angel_engine.db.models import AIInteraction, Investigation, User
from angel_engine.db.session import set_investigation_scope
from angel_engine.jobs.queue import PermanentJobError
from angel_engine.jobs.registry import JobContext, handler


def _ids(payload: dict[str, Any]) -> tuple[uuid.UUID, uuid.UUID]:
    try:
        return uuid.UUID(payload["interaction_id"]), uuid.UUID(payload["investigation_id"])
    except (KeyError, ValueError) as exc:
        raise PermanentJobError("invalid payload") from exc


async def _load(
    svc: Services, db: Any, interaction_id: uuid.UUID, inv_id: uuid.UUID
) -> tuple[AIInteraction | None, Investigation | None, FieldCipher | None]:
    await set_investigation_scope(db, [inv_id])
    interaction = (
        await db.execute(
            select(AIInteraction)
            .where(AIInteraction.id == interaction_id, AIInteraction.investigation_id == inv_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    inv = await db.get(Investigation, inv_id)
    if interaction is None or inv is None or inv.status == InvestigationStatus.DELETED.value:
        return None, None, None
    try:
        return interaction, inv, await svc.vault.investigation_cipher(db, inv_id)
    except KeyDestroyedError:
        return None, None, None


def _event(interaction: AIInteraction, outcome: str, **details: Any) -> AuditEvent:
    return AuditEvent(
        action="ai.completed" if outcome == "success" else "ai.failed",
        actor_type="worker",
        investigation_id=interaction.investigation_id,
        target_type="ai_interaction",
        target_id=str(interaction.id),
        outcome=outcome,
        details={"task": interaction.task, "provider": interaction.provider, **details},
    )


async def _fail(svc: Services, interaction_id: uuid.UUID, inv_id: uuid.UUID, code: str) -> dict[str, Any]:
    async with svc.db.session("worker") as db:
        interaction, _inv, _ = await _load(svc, db, interaction_id, inv_id)
        if interaction is None:
            return {"skipped": "deleted"}
        interaction.status, interaction.error_code, interaction.completed_at = "failed", code, utcnow()
        await append_now(db, svc.audit_key, [_event(interaction, "failure", error=code)])
    return {"status": "failed", "error": code}


@handler("ai.run")
async def run_assistant(ctx: JobContext, payload: dict[str, Any]) -> dict[str, Any]:
    svc = ctx.services
    interaction_id, inv_id = _ids(payload)
    async with svc.db.session("worker") as db:
        interaction, inv, cipher = await _load(svc, db, interaction_id, inv_id)
        if interaction is None or inv is None or cipher is None:
            return {"skipped": "missing"}
        if interaction.status not in ("pending", "running"):
            return {"skipped": interaction.status}
        interaction.status = "running"
        prepared, preview = await service.prepare(svc, db, cipher, inv, interaction)
    llm = svc.get("llm")
    if llm is None:
        return await _fail(svc, interaction_id, inv_id, "ai_unavailable")
    if preview is not None:
        key, file_key = preview
        prepared.image_jpeg = FieldCipher.decrypt_blob(file_key, await svc.get("storage").get(key), object_key=key)
    await ctx.progress("thinking", documents=len(prepared.docs))
    try:
        raw = await service.call(llm, prepared)
    except ProviderFailed as exc:
        return await _fail(svc, interaction_id, inv_id, exc.code)
    except ProviderUnavailable:
        if ctx.job.attempts >= ctx.job.max_attempts:
            return await _fail(svc, interaction_id, inv_id, "provider_unavailable")
        raise
    outcome = service.validate(prepared, raw, inv)
    await ctx.progress("saving")
    async with svc.db.session("worker") as db:
        interaction, inv, cipher = await _load(svc, db, interaction_id, inv_id)
        if interaction is None or inv is None or cipher is None:
            return {"skipped": "deleted"}
        user = await db.get(User, interaction.user_id) if interaction.user_id else None
        created = await service.store(svc, db, cipher, inv, interaction, user, prepared, outcome)
        await append_now(
            db,
            svc.audit_key,
            [
                _event(
                    interaction,
                    "success",
                    model=interaction.model,
                    input_tokens=interaction.input_tokens,
                    output_tokens=interaction.output_tokens,
                    grounding=interaction.grounding,
                    context_documents=len(prepared.docs),
                    cited=len(interaction.cited_evidence_ids),
                    proposals=created,
                )
            ],
        )
    return {"status": "completed", "grounding": outcome.grounding.value, "proposals": created}
