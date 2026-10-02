"""Collection runs: validate and screen a query, then queue it for the egress worker.

Every query passes the acceptable-use policy (``collection_query`` surface) with the investigation's
context. Person-oriented connectors (profile lookups) need a recorded purpose, and in restricted mode
(individual subjects) they wait for a supervisor's approval. Rate limits (fail closed): 30 runs per hour
per user and 300 per day per investigation.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from angel_engine.app_state import Services
from angel_engine.core.enums import JobQueue
from angel_engine.core.ids import new_id
from angel_engine.core.problems import ConflictState, ServiceUnavailable, ValidationProblem
from angel_engine.crypto.envelope import FieldCipher
from angel_engine.crypto.keyed_hash import content_mac
from angel_engine.db.models import CollectionRun, Investigation, User
from angel_engine.infra.ratelimit.gcra import COLLECTION_INVESTIGATION, COLLECTION_USER
from angel_engine.jobs.queue import enqueue
from angel_engine.osint.registry import ConnectorRegistry
from angel_engine.osint.types import InputType
from angel_engine.policy.types import Decision, PolicyContext, Surface
from angel_engine.policy_gate import require_acknowledgement, screen

MIN_PURPOSE_NOTE = 20


def registry(svc: Services) -> ConnectorRegistry:
    reg = svc.get("connectors")
    if reg is None:
        raise ServiceUnavailable("Public-source collection is not available.", code="collection_unavailable")
    return reg  # type: ignore[no-any-return]


async def create_run(
    svc: Services,
    db: AsyncSession,
    cipher: FieldCipher,
    inv: Investigation,
    user: User,
    *,
    connector_id: str,
    input_type: str,
    query: str,
    params: dict[str, Any] | None = None,
    purpose_note: str | None = None,
    acknowledge_policy_notices: bool = False,
    origin_image_id: uuid.UUID | None = None,
    origin_clue_id: uuid.UUID | None = None,
    idempotency_key: str | None = None,
    actor_event: Any = None,
) -> tuple[CollectionRun, Decision]:
    reg = registry(svc)
    connector = reg.get(connector_id)
    if connector is None:
        raise ValidationProblem("Unknown source.", code="unknown_connector")
    status = reg.status(connector)
    if status.status != "ready":
        raise ConflictState(status.reason or "This source is not available.", code=f"connector_{status.status}")
    info = connector.info
    if input_type not in {t.value for t in info.input_types}:
        raise ValidationProblem(f"{info.name} does not accept this kind of input.", code="unsupported_input")
    if inv.restricted_mode and not info.allowed_in_restricted_mode:
        raise ConflictState(
            f"{info.name} is not available in restricted mode (individual subject).", code="restricted_mode"
        )
    query = query.strip()
    if not query or len(query) > 500:
        raise ValidationProblem("Queries must be 1–500 characters.", code="invalid_query")
    params = {str(k)[:40]: str(v)[:200] for k, v in (params or {}).items()}
    if info.person_oriented and len((purpose_note or "").strip()) < MIN_PURPOSE_NOTE:
        raise ValidationProblem(
            "Profile lookups need a short note explaining why this account is relevant.", code="purpose_note_required"
        )
    if idempotency_key:
        existing = (
            await db.execute(
                select(CollectionRun).where(
                    CollectionRun.investigation_id == inv.id, CollectionRun.idempotency_key == idempotency_key
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            return existing, Decision.ALLOW
    from angel_engine.api.deps import enforce_rate_limit

    await enforce_rate_limit(svc, f"collect:user:{user.id}", COLLECTION_USER)
    await enforce_rate_limit(svc, f"collect:inv:{inv.id}", COLLECTION_INVESTIGATION)
    screened = " ".join([query, *params.values(), purpose_note or ""]).strip()
    result, decision = await screen(
        svc,
        db,
        user,
        screened,
        PolicyContext(
            surface=Surface.COLLECTION_QUERY, subject_type=inv.subject_type, restricted_mode=inv.restricted_mode
        ),
        investigation_id=inv.id,
        target_type="collection_run",
        actor_event=actor_event,
    )
    require_acknowledgement(result, acknowledge_policy_notices)
    needs_review = result.decision == Decision.REVIEW or (info.person_oriented and inv.restricted_mode)
    run_id = new_id()
    run = CollectionRun(
        id=run_id,
        investigation_id=inv.id,
        connector_id=connector_id,
        input_type=input_type,
        query=cipher.seal(query, table="collection_runs", column="query", row_id=run_id),
        params=cipher.seal_json(params, table="collection_runs", column="params", row_id=run_id) if params else None,
        purpose_note=cipher.seal_optional(
            purpose_note.strip() if purpose_note else None,
            table="collection_runs",
            column="purpose_note",
            row_id=run_id,
        ),
        policy_decision_id=decision.id,
        status="pending_review" if needs_review else "queued",
        requested_by=user.id,
        origin_image_id=origin_image_id,
        origin_clue_id=origin_clue_id,
        idempotency_key=idempotency_key,
    )
    db.add(run)
    await db.flush()
    decision.target_id = run_id
    if not needs_review:
        await queue_run(db, run, user.id)
    return run, result.decision


async def queue_run(db: AsyncSession, run: CollectionRun, actor_id: uuid.UUID | None) -> None:
    run.status = "queued"
    await enqueue(
        db,
        queue=JobQueue.EGRESS,
        kind="collection.run",
        payload={"run_id": str(run.id), "investigation_id": str(run.investigation_id)},
        investigation_id=run.investigation_id,
        created_by=actor_id,
        idempotency_key=f"run:{run.id}",
        max_attempts=3,
    )


def query_fingerprint(cipher: FieldCipher, query: str) -> str:
    """Content-free audit reference to a query (keyed, dies with the investigation key)."""
    return content_mac(cipher, query.casefold().strip()).hex()[:16]


def validate_input(input_type: str) -> None:
    if input_type not in {t.value for t in InputType}:
        raise ValidationProblem("Unknown input type.", code="invalid_input_type")
