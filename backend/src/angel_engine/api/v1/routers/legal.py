"""Legal documents (public) and acceptance of new versions."""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from angel_engine.api.deps import CurrentPrincipal, DbSession
from angel_engine.core.clock import utcnow
from angel_engine.core.problems import ValidationProblem
from angel_engine.db.models import Attestation
from angel_engine.legal.documents import current_versions, load_documents

router = APIRouter(tags=["legal"])


class LegalDocOut(BaseModel):
    kind: str
    title: str
    version: str
    effective: str
    sha256: str
    body_markdown: str


@router.get("/legal/documents/current", openapi_extra={"x-public": True})
async def legal_documents() -> list[LegalDocOut]:
    return [
        LegalDocOut(
            kind=d.kind, title=d.title, version=d.version, effective=d.effective, sha256=d.sha256, body_markdown=d.body
        )
        for d in load_documents().values()
    ]


class AcceptTermsIn(BaseModel):
    terms_version: str
    acceptable_use_version: str
    attest_lawful_use: bool


@router.post("/me/attestations")
async def accept_terms(body: AcceptTermsIn, principal: CurrentPrincipal, db: DbSession) -> dict[str, str]:
    versions = current_versions()
    if body.terms_version != versions["terms"] or body.acceptable_use_version != versions["acceptable_use"]:
        raise ValidationProblem("Please accept the current versions of the documents.", code="stale_document_version")
    if not body.attest_lawful_use:
        raise ValidationProblem("You must confirm lawful use.", code="attestation_required")
    principal.user.terms_version_accepted = versions["terms"]
    principal.user.terms_accepted_at = utcnow()
    db.add(
        Attestation(
            user_id=principal.user_id,
            kind="account",
            document_versions=versions,
            statements=["accept_terms", "attest_lawful_use"],
            ip_pseudonym=principal.ip_pseudonym,
        )
    )
    principal.audit(db, "legal.terms_accepted", details={"terms_version": versions["terms"]})
    return {"status": "accepted", "terms_version": versions["terms"]}
