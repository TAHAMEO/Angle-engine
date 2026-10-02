"""Direct database factories for integration tests (bypassing the API where convenient)."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from angel_engine.app_state import Services
from angel_engine.core.clock import utcnow
from angel_engine.core.ids import new_id
from angel_engine.crypto.envelope import FieldCipher
from angel_engine.db.models import EvidenceItem, Investigation, InvestigationMember, Source
from angel_engine.db.session import set_investigation_scope


async def make_investigation(
    services: Services,
    owner_id: uuid.UUID,
    *,
    status: str = "active",
    subject_type: str = "organization",
    title: str = "Test investigation",
) -> uuid.UUID:
    async with services.db.session("app") as db:
        seq = (
            await db.execute(
                text(
                    "INSERT INTO investigation_ref_counters (year, last_seq) VALUES (2026, 1) "
                    "ON CONFLICT (year) DO UPDATE SET last_seq = investigation_ref_counters.last_seq + 1 "
                    "RETURNING last_seq"
                )
            )
        ).scalar_one()
        inv = Investigation(
            id=new_id(),
            ref_year=2026,
            ref_seq=seq,
            title=title,
            purpose=b"",
            purpose_category="due_diligence",
            lawful_basis="legitimate_interest",
            subject_type=subject_type,
            restricted_mode=subject_type == "individual",
            status=status,
            owner_id=owner_id,
        )
        db.add(inv)
        await db.flush()
        cipher = await services.vault.create_investigation_key(db, inv.id)
        inv.purpose = cipher.seal(
            "Verify the public footprint of a fictional company for a due-diligence test.",
            table="investigations",
            column="purpose",
            row_id=inv.id,
        )
        db.add(InvestigationMember(investigation_id=inv.id, user_id=owner_id, role="owner"))
        return inv.id


async def scoped_session_add_source(
    db: AsyncSession, cipher: FieldCipher, inv_id: uuid.UUID, url: str = "https://northwind-coffee.example/"
) -> Source:
    await set_investigation_scope(db, [inv_id])
    sid = new_id()
    src = Source(
        id=sid,
        investigation_id=inv_id,
        label_seq=1,
        url=cipher.seal(url, table="sources", column="url", row_id=sid),
        url_mac=cipher.mac("ae/url/v1", url + str(sid)),
        host="northwind-coffee.example",
        registrable_domain="northwind-coffee.example",
        source_category="websites",
        connector_id="web_capture",
        first_captured_at=utcnow(),
        last_captured_at=utcnow(),
    )
    db.add(src)
    await db.flush()
    return src


async def add_evidence(
    db: AsyncSession,
    cipher: FieldCipher,
    inv_id: uuid.UUID,
    source_id: uuid.UUID,
    text_value: str = "Founded in 2016 in Lisbon.",
    **extra: Any,
) -> EvidenceItem:
    eid = new_id()
    ev = EvidenceItem(
        id=eid,
        investigation_id=inv_id,
        label_seq=1,
        source_id=source_id,
        evidence_type="text_excerpt",
        provenance="source_reported",
        excerpt=cipher.seal(text_value, table="evidence_items", column="excerpt", row_id=eid),
        content_mac=cipher.mac("ae/content/v1", text_value + str(eid)),
        captured_at=utcnow(),
        **extra,
    )
    db.add(ev)
    await db.flush()
    return ev


async def add_member(services: Services, investigation_id: uuid.UUID, user_id: uuid.UUID, role: str = "editor") -> None:
    async with services.db.session("app") as db:
        db.add(InvestigationMember(investigation_id=investigation_id, user_id=user_id, role=role))
