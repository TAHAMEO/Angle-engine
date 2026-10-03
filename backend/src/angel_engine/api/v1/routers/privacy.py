"""Privacy operations: export my data, data-subject lookup and the investigation register for administrators.

Administrators never read investigation content. The data-subject lookup computes each investigation's own keyed
hashes (URL, entity canonical forms) for a value supplied in a request and reports only *where* it occurs, so an
abuse or data-subject request can be routed to the right owner, put under legal hold or handled by deletion.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select

from angel_engine.api.deps import (
    CurrentPrincipal,
    DbSession,
    Principal,
    enforce_rate_limit,
    require,
    require_recent_reauth,
)
from angel_engine.authz.permissions import Perm
from angel_engine.core.clock import utcnow
from angel_engine.core.enums import InvestigationStatus
from angel_engine.core.problems import Conflict, NotFound, ValidationProblem
from angel_engine.crypto.envelope import FieldCipher, KeyDestroyedError
from angel_engine.crypto.keyed_hash import canonical_mac, url_mac
from angel_engine.db.models import BlobDeletion, DataExport, Entity, Investigation, InvestigationMember, Source, User
from angel_engine.db.session import set_investigation_scope
from angel_engine.entities.service import canonicalize
from angel_engine.evidence.urls import UrlError, normalize_url
from angel_engine.exports.account import request_export
from angel_engine.infra.ratelimit.gcra import EXPORTS_USER

router = APIRouter(tags=["privacy"])
UserManager = Annotated[Principal, Depends(require(Perm.USER_MANAGE))]


# --------------------------------------------------------------------------------------------------
# Export my data
# --------------------------------------------------------------------------------------------------
class DataExportOut(BaseModel):
    id: str
    status: str
    created_at: datetime
    expires_at: datetime
    downloaded_at: datetime | None


def _export_out(export: DataExport) -> DataExportOut:
    status = "expired" if export.status in ("pending", "ready") and export.expires_at <= utcnow() else export.status
    return DataExportOut(
        id=str(export.id),
        status=status,
        created_at=export.created_at,
        expires_at=export.expires_at,
        downloaded_at=export.downloaded_at,
    )


@router.post("/me/data-exports", status_code=202)
async def create_data_export(principal: CurrentPrincipal, db: DbSession) -> DataExportOut:
    """Request an archive of your account data (needs a recent password confirmation)."""
    require_recent_reauth(principal)
    await enforce_rate_limit(principal.services, f"user:{principal.user_id}:exports", EXPORTS_USER)
    export = await request_export(principal.services, db, principal.user_id)
    principal.audit(db, "account.data_export_requested", target_type="data_export", target_id=str(export.id))
    return _export_out(export)


@router.get("/me/data-exports")
async def list_data_exports(principal: CurrentPrincipal, db: DbSession) -> list[DataExportOut]:
    rows = (
        (
            await db.execute(
                select(DataExport)
                .where(DataExport.user_id == principal.user_id)
                .order_by(DataExport.created_at.desc())
                .limit(20)
            )
        )
        .scalars()
        .all()
    )
    return [_export_out(r) for r in rows]


@router.get(
    "/me/data-exports/{export_id}/download",
    response_class=Response,
    responses={200: {"content": {"application/zip": {}}, "description": "The account archive (single use)."}},
)
async def download_data_export(export_id: uuid.UUID, principal: CurrentPrincipal, db: DbSession) -> Response:
    """Download the archive once. The stored copy is deleted afterwards."""
    require_recent_reauth(principal)
    export = (
        await db.execute(
            select(DataExport)
            .where(DataExport.id == export_id, DataExport.user_id == principal.user_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if export is None:
        raise NotFound()
    if export.status == "downloaded":
        raise Conflict("This export was already downloaded. Request a new one.", code="export_already_downloaded")
    if export.status != "ready" or export.expires_at <= utcnow() or not export.object_key or not export.file_key:
        raise Conflict("This export is not ready or has expired.", code="export_not_ready")
    system = await principal.services.vault.system_cipher(db, "system_secrets")
    file_key = system.open_bytes(export.file_key, table="data_exports", column="file_key", row_id=export.id)
    blob = await principal.services.get("storage").get(export.object_key)
    content = FieldCipher.decrypt_blob(file_key, blob, object_key=export.object_key)
    db.add(BlobDeletion(object_key=export.object_key, reason="export_downloaded"))
    export.status, export.downloaded_at, export.object_key, export.file_key = "downloaded", utcnow(), None, None
    principal.audit(db, "account.data_export_downloaded", target_type="data_export", target_id=str(export.id))
    return Response(
        content=content,
        media_type="application/zip",
        headers={
            "Content-Disposition": 'attachment; filename="angel-engine-account-export.zip"',
            "Cache-Control": "no-store",
        },
    )


# --------------------------------------------------------------------------------------------------
# Investigation register (metadata only)
# --------------------------------------------------------------------------------------------------
class AdminInvestigationOut(BaseModel):
    id: str
    ref: str
    status: str
    subject_type: str
    purpose_category: str
    restricted_mode: bool
    legal_hold: bool
    owner_name: str | None
    member_count: int
    created_at: datetime
    closed_at: datetime | None


@router.get("/admin/investigations")
async def admin_investigations(
    principal: UserManager,
    db: DbSession,
    status: Annotated[InvestigationStatus | None, Query()] = None,
    ref: Annotated[str | None, Query(max_length=20)] = None,
    legal_hold: bool | None = None,
) -> list[AdminInvestigationOut]:
    """Investigations as metadata only (no titles, purposes or content) — for legal holds and abuse handling."""
    members = (
        select(InvestigationMember.investigation_id, func.count().label("n"))
        .group_by(InvestigationMember.investigation_id)
        .subquery()
    )
    stmt = (
        select(Investigation, User.display_name, members.c.n)
        .outerjoin(User, User.id == Investigation.owner_id)
        .outerjoin(members, members.c.investigation_id == Investigation.id)
        .order_by(Investigation.created_at.desc())
        .limit(200)
    )
    if status is not None:
        stmt = stmt.where(Investigation.status == status.value)
    if ref:
        stmt = stmt.where(Investigation.public_ref == ref.strip().upper())
    if legal_hold is not None:
        stmt = stmt.where(Investigation.legal_hold.is_(legal_hold))
    rows = (await db.execute(stmt)).all()
    principal.audit(db, "admin.investigation_register_viewed", details={"results": len(rows)})
    return [
        AdminInvestigationOut(
            id=str(inv.id),
            ref=inv.public_ref,
            status=inv.status,
            subject_type=inv.subject_type,
            purpose_category=inv.purpose_category,
            restricted_mode=inv.restricted_mode,
            legal_hold=inv.legal_hold,
            owner_name=owner,
            member_count=int(n or 0),
            created_at=inv.created_at,
            closed_at=inv.closed_at,
        )
        for inv, owner, n in rows
    ]


# --------------------------------------------------------------------------------------------------
# Data-subject lookup
# --------------------------------------------------------------------------------------------------
class LookupIn(BaseModel):
    kind: Literal["url", "domain", "username", "name"]
    value: str = Field(min_length=2, max_length=500)
    platform: str | None = Field(default=None, max_length=60)
    reason: Literal["data_subject_request", "abuse_report", "legal_request"]
    abuse_report_id: uuid.UUID | None = None


class LookupMatch(BaseModel):
    investigation_id: str
    ref: str
    status: str
    legal_hold: bool
    owner_name: str | None
    sources: int
    entities: int


class LookupOut(BaseModel):
    checked: int
    matches: list[LookupMatch]


def _entity_keys(kind: str, value: str, platform: str | None) -> list[tuple[str, str]]:
    """(entity type, canonical form) pairs the value could have been stored under."""
    if kind == "url":
        return [("webpage", canonicalize("webpage", value))]
    if kind == "domain":
        return [(t, canonicalize(t, value)) for t in ("domain", "website")]
    if kind == "username":
        keys = [("username", canonicalize("username", value))]
        if platform:
            keys.append(("username", canonicalize("username", value, {"platform": platform})))
        return keys
    return [(t, canonicalize(t, value)) for t in ("public_figure", "organization", "brand")]


async def _count_matches(
    db: DbSession, cipher: FieldCipher, inv: Investigation, body: LookupIn, url: str | None
) -> tuple[int, int]:
    await set_investigation_scope(db, [inv.id])
    sources = 0
    if body.kind == "url" and url:
        sources = int(
            (
                await db.execute(
                    select(func.count())
                    .select_from(Source)
                    .where(Source.investigation_id == inv.id, Source.url_mac == url_mac(cipher, url))
                )
            ).scalar_one()
        )
    elif body.kind == "domain":
        domain = body.value.strip().lower().removeprefix("www.")
        sources = int(
            (
                await db.execute(
                    select(func.count())
                    .select_from(Source)
                    .where(
                        Source.investigation_id == inv.id,
                        or_(Source.registrable_domain == domain, Source.host == domain),
                    )
                )
            ).scalar_one()
        )
    entity_filters = [
        (Entity.type == entity_type) & (Entity.canonical_mac == canonical_mac(cipher, entity_type, canonical))
        for entity_type, canonical in _entity_keys(body.kind, url or body.value, body.platform)
    ]
    entities = int(
        (
            await db.execute(
                select(func.count()).select_from(Entity).where(Entity.investigation_id == inv.id, or_(*entity_filters))
            )
        ).scalar_one()
    )
    return sources, entities


@router.post("/admin/data-subject-lookup")
async def data_subject_lookup(body: LookupIn, principal: UserManager, db: DbSession) -> LookupOut:
    """Find which investigations reference a URL, domain, public username or name — without reading content.

    Needs a recent password confirmation; the lookup (kind, reason and number of matches — never the value) is
    recorded in the audit log.
    """
    require_recent_reauth(principal)
    url: str | None = None
    if body.kind == "url":
        try:
            url = normalize_url(body.value).url
        except UrlError as exc:
            raise ValidationProblem("Enter a public http(s) URL.", code="invalid_url") from exc
    investigations = (
        await db.execute(
            select(Investigation, User.display_name)
            .outerjoin(User, User.id == Investigation.owner_id)
            .where(Investigation.status != InvestigationStatus.DELETED.value)
            .order_by(Investigation.created_at)
        )
    ).all()
    matches: list[LookupMatch] = []
    for inv, owner in investigations:
        try:
            cipher = await principal.services.vault.investigation_cipher(db, inv.id)
        except KeyDestroyedError:
            continue
        sources, entities = await _count_matches(db, cipher, inv, body, url)
        if sources or entities:
            matches.append(
                LookupMatch(
                    investigation_id=str(inv.id),
                    ref=inv.public_ref,
                    status=inv.status,
                    legal_hold=inv.legal_hold,
                    owner_name=owner,
                    sources=sources,
                    entities=entities,
                )
            )
    await set_investigation_scope(db, [])
    principal.audit(
        db,
        "admin.data_subject_lookup",
        details={
            "kind": body.kind,
            "reason": body.reason,
            "abuse_report_id": str(body.abuse_report_id) if body.abuse_report_id else None,
            "checked": len(investigations),
            "matches": len(matches),
        },
    )
    return LookupOut(checked=len(investigations), matches=matches)
