"""Public entities: organizations, websites, domains, usernames, landmarks, events, broad locations …

There is deliberately no entity type for a private person. ``public_figure`` entities require a stated
public-role basis (e.g. "CEO of ACME, per the 2025 annual report") and are only ever described through
that role. Names of intrinsically public entity types are stored in plaintext (searchable); all other
names are encrypted. Entities are de-duplicated per investigation with a keyed MAC of a canonical form.
"""

from __future__ import annotations

import re
import unicodedata
import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from angel_engine.core.enums import PLAINTEXT_ENTITY_TYPES, EntityType
from angel_engine.core.ids import new_id
from angel_engine.core.problems import ConflictState, ValidationProblem
from angel_engine.crypto.envelope import FieldCipher
from angel_engine.crypto.keyed_hash import canonical_mac
from angel_engine.db.models import Entity, EntityMention, Fact, Investigation, Relationship
from angel_engine.evidence.service import redaction_mode
from angel_engine.evidence.urls import UrlError, normalize_url
from angel_engine.guard import RedactionContext, SourceKind, redact_text

PLAINTEXT = frozenset(t.value for t in PLAINTEXT_ENTITY_TYPES)
LOCATION_LEVELS = ("country", "admin1", "locality", "landmark")
MAX_NAME = 300
_LEGAL_SUFFIXES = re.compile(
    r"[,\s]+(?:inc|incorporated|corp|corporation|co|company|ltd|limited|llc|l\.l\.c|plc|gmbh|ag|sa|s\.a|"
    r"sas|sarl|srl|spa|s\.p\.a|bv|b\.v|nv|n\.v|oy|ab|as|a/s|lda|ltda|pty|kk|k\.k|sl|s\.l)\.?$",
    re.IGNORECASE,
)
_SPACE = re.compile(r"\s+")


class EntityError(ValidationProblem):
    pass


def _fold(value: str) -> str:
    return _SPACE.sub(" ", unicodedata.normalize("NFKC", value).casefold()).strip(" .,;:'\"")


def canonicalize(entity_type: str, name: str, attributes: dict[str, Any] | None = None) -> str:
    """Canonical key used for de-duplication (never displayed)."""
    attrs = attributes or {}
    folded = _fold(name)
    if entity_type in (EntityType.DOMAIN.value, EntityType.WEBSITE.value):
        host = folded.removeprefix("https://").removeprefix("http://").split("/")[0].removeprefix("www.")
        try:
            return host.encode("idna").decode("ascii")
        except UnicodeError:
            return host
    if entity_type == EntityType.WEBPAGE.value:
        try:
            return normalize_url(name).url
        except UrlError:
            return folded
    if entity_type == EntityType.USERNAME.value:
        platform = _fold(str(attrs.get("platform", "")))
        handle = folded.lstrip("@")
        return f"{platform}:{handle}" if platform else handle
    if entity_type in (EntityType.ORGANIZATION.value, EntityType.BRAND.value):
        previous = None
        while previous != folded:
            previous, folded = folded, _LEGAL_SUFFIXES.sub("", folded).strip(" .,")
        return folded
    if entity_type == EntityType.LOCATION.value:
        return f"{attrs.get('location_level', '')}:{attrs.get('country', '')}:{folded}"
    return folded


@dataclass(frozen=True, slots=True)
class EntityInput:
    type: str
    name: str
    attributes: dict[str, Any] = field(default_factory=dict)
    location_level: str | None = None
    country: str | None = None
    public_role_basis: str | None = None
    created_via: str = "system"


def _validate(inv: Investigation, data: EntityInput) -> None:
    if data.type not in {t.value for t in EntityType}:
        raise EntityError("Unknown entity type.", code="invalid_entity_type")
    if data.type == EntityType.PUBLIC_FIGURE.value and not (data.public_role_basis or "").strip():
        raise EntityError(
            "Describe the public role (and its source) for a public figure.", code="public_role_basis_required"
        )
    if data.type == EntityType.LOCATION.value and data.location_level not in LOCATION_LEVELS:
        raise EntityError(
            "Locations are recorded at country, region, locality or landmark level only.", code="invalid_location_level"
        )
    if data.country is not None and not re.fullmatch(r"[A-Z]{2}", data.country):
        raise EntityError("Use an ISO 3166-1 alpha-2 country code.", code="invalid_country")
    if not data.name.strip() or len(data.name) > MAX_NAME:
        raise EntityError("Entity names must be 1–300 characters.", code="invalid_entity_name")


async def _resolve_merged(db: AsyncSession, entity: Entity) -> Entity:
    seen: set[uuid.UUID] = set()
    while entity.merged_into_id is not None and entity.id not in seen:
        seen.add(entity.id)
        target = await db.get(Entity, entity.merged_into_id)
        if target is None:
            break
        entity = target
    return entity


async def upsert_entity(
    db: AsyncSession, cipher: FieldCipher, inv: Investigation, data: EntityInput
) -> tuple[Entity, bool]:
    _validate(inv, data)
    red = redact_text(data.name, mode=redaction_mode(inv), context=RedactionContext(source_kind=SourceKind.WEB))
    if red.redacted:
        # Personal data (an email, phone number, street address …) is never an entity name.
        raise EntityError(
            "This name contains personal or sensitive data and cannot be stored as an entity.",
            code="sensitive_entity_name",
            redacted=sorted(red.counts),
        )
    name = data.name.strip()
    attrs = {**data.attributes, "location_level": data.location_level, "country": data.country}
    canonical = canonicalize(data.type, name, attrs)
    mac = canonical_mac(cipher, data.type, canonical)
    stmt = select(Entity).where(
        Entity.investigation_id == inv.id, Entity.type == data.type, Entity.canonical_mac == mac
    )
    existing = (await db.execute(stmt)).scalar_one_or_none()
    if existing is not None:
        return await _resolve_merged(db, existing), False
    eid = new_id()
    plaintext = data.type in PLAINTEXT
    entity = Entity(
        id=eid,
        investigation_id=inv.id,
        type=data.type,
        name=name if plaintext else None,
        name_enc=None if plaintext else cipher.seal(name, table="entities", column="name_enc", row_id=eid),
        canonical_mac=mac,
        location_level=data.location_level,
        country=data.country,
        public_role_basis=cipher.seal_optional(
            data.public_role_basis, table="entities", column="public_role_basis", row_id=eid
        ),
        attributes=cipher.seal_json(data.attributes, table="entities", column="attributes", row_id=eid)
        if data.attributes
        else None,
        created_via=data.created_via,
    )
    db.add(entity)
    await db.flush()
    return entity, True


def entity_name(cipher: FieldCipher, entity: Entity) -> str:
    if entity.name is not None:
        return entity.name
    return cipher.open(entity.name_enc or b"", table="entities", column="name_enc", row_id=entity.id)


def entity_view(cipher: FieldCipher, entity: Entity) -> dict[str, Any]:
    attributes = (
        cipher.open_json(entity.attributes, table="entities", column="attributes", row_id=entity.id)
        if entity.attributes
        else {}
    )
    return {
        "id": str(entity.id),
        "type": entity.type,
        "name": entity_name(cipher, entity),
        "location_level": entity.location_level,
        "country": entity.country,
        "public_role_basis": cipher.open_optional(
            entity.public_role_basis, table="entities", column="public_role_basis", row_id=entity.id
        ),
        "attributes": attributes,
        "merged_into_id": str(entity.merged_into_id) if entity.merged_into_id else None,
        "created_via": entity.created_via,
        "created_at": entity.created_at,
    }


async def add_mention(
    db: AsyncSession, inv: Investigation, entity_id: uuid.UUID, evidence_id: uuid.UUID
) -> EntityMention | None:
    stmt = select(EntityMention).where(EntityMention.entity_id == entity_id, EntityMention.evidence_id == evidence_id)
    if (await db.execute(stmt)).scalar_one_or_none() is not None:
        return None
    mention = EntityMention(id=new_id(), investigation_id=inv.id, entity_id=entity_id, evidence_id=evidence_id)
    db.add(mention)
    await db.flush()
    return mention


async def merge_entities(db: AsyncSession, inv: Investigation, source: Entity, target: Entity) -> int:
    """Merge ``source`` into ``target``: repoint mentions, facts and relationships. Returns edges moved."""
    if source.id == target.id:
        raise ConflictState("An entity cannot be merged into itself.", code="merge_self")
    if source.type != target.type:
        raise ConflictState("Only entities of the same type can be merged.", code="merge_type_mismatch")
    if target.merged_into_id is not None:
        raise ConflictState("The target entity has itself been merged.", code="merge_target_merged")
    mentions = (await db.execute(select(EntityMention).where(EntityMention.entity_id == source.id))).scalars().all()
    existing = {
        m.evidence_id
        for m in (await db.execute(select(EntityMention).where(EntityMention.entity_id == target.id))).scalars()
    }
    for mention in mentions:
        if mention.evidence_id in existing:
            await db.delete(mention)
        else:
            mention.entity_id = target.id
    await db.execute(
        update(Fact).where(Fact.investigation_id == inv.id, Fact.entity_id == source.id).values(entity_id=target.id)
    )
    from angel_engine.graph.service import repoint_relationships

    moved = await repoint_relationships(db, inv, source.id, target.id)
    source.merged_into_id = target.id
    await db.flush()
    return moved


async def relationship_count(db: AsyncSession, entity_id: uuid.UUID) -> int:
    from sqlalchemy import func, or_

    stmt = (
        select(func.count())
        .select_from(Relationship)
        .where(or_(Relationship.from_entity_id == entity_id, Relationship.to_entity_id == entity_id))
    )
    return int((await db.execute(stmt)).scalar_one())
