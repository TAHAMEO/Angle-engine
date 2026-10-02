"""Public contract of the OSINT research engine (connectors + normalization).

Connectors only use official APIs or robots-permitted public pages through
:class:`angel_engine.infra.http.safe_client.SafeHttpClient`. They never send cookies or credentials
(other than the connector's own API key), never solve CAPTCHAs, never bypass logins or paywalls.
Pages that require authentication or that robots.txt disallows are returned as
:class:`ManualReference` items for the investigator to review themselves.

Connectors return *normalized, still-unredacted* records; the ingestion service (not the connector)
applies the sensitive-data guard before anything is persisted.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class SourceCategory(StrEnum):
    WEBSITES = "websites"
    NEWS_ARTICLES = "news_articles"
    PUBLIC_SOCIAL_MEDIA = "public_social_media"
    PUBLIC_PROFILES = "public_profiles"
    PUBLIC_DOCUMENTS = "public_documents"
    PUBLIC_COMPANY_INFORMATION = "public_company_information"
    PUBLIC_GOVERNMENT_INFORMATION = "public_government_information"
    PUBLIC_DIRECTORIES = "public_directories"
    PUBLIC_FORUMS = "public_forums"
    PUBLIC_IMAGE_SOURCES = "public_image_sources"
    SEARCH_ENGINE_RESULTS = "search_engine_results"


CATEGORY_LABELS: dict[SourceCategory, str] = {
    SourceCategory.WEBSITES: "Websites",
    SourceCategory.NEWS_ARTICLES: "News articles",
    SourceCategory.PUBLIC_SOCIAL_MEDIA: "Public social-media pages",
    SourceCategory.PUBLIC_PROFILES: "Public profiles",
    SourceCategory.PUBLIC_DOCUMENTS: "Public documents",
    SourceCategory.PUBLIC_COMPANY_INFORMATION: "Public company information",
    SourceCategory.PUBLIC_GOVERNMENT_INFORMATION: "Public government information",
    SourceCategory.PUBLIC_DIRECTORIES: "Public directories",
    SourceCategory.PUBLIC_FORUMS: "Public forums",
    SourceCategory.PUBLIC_IMAGE_SOURCES: "Public image sources",
    SourceCategory.SEARCH_ENGINE_RESULTS: "Search-engine results",
}


class InputType(StrEnum):
    KEYWORD = "keyword"
    DOMAIN = "domain"
    URL = "url"
    USERNAME = "username"
    ORGANIZATION = "organization"
    PLACE = "place"            # broad, user-typed place names only
    IMAGE = "image"            # sanitized preview (reverse-image providers)


class EvidenceType(StrEnum):
    TEXT_EXCERPT = "text_excerpt"
    PAGE_CAPTURE = "page_capture"
    DOCUMENT_EXCERPT = "document_excerpt"
    REGISTRY_RECORD = "registry_record"
    SEARCH_RESULT = "search_result"
    OCR_TEXT = "ocr_text"
    IMAGE_CLUE = "image_clue"
    METADATA = "metadata"
    IMAGE_MATCH = "image_match"


class AccessStatus(StrEnum):
    CAPTURED = "captured"
    REFERENCE_ONLY = "reference_only"
    LOGIN_REQUIRED = "login_required"
    ROBOTS_DISALLOWED = "robots_disallowed"
    PAYWALLED = "paywalled"


@dataclass(frozen=True, slots=True)
class ConnectorQuery:
    input_type: InputType
    value: str
    limit: int = 20
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class EntityDraft:
    """Public entity only (organization, website, domain, username, landmark, event, …)."""

    type: str
    name: str
    canonical: str
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class FactDraft:
    """Structured attribute used for deterministic corroboration/contradiction checks."""

    entity_canonical: str
    entity_type: str
    attribute: str              # registry key, e.g. "org.inception", "domain.registration_date"
    value: Any
    precision: str | None = None   # "day" | "month" | "year" for dates
    valid_from: str | None = None
    valid_to: str | None = None


@dataclass(frozen=True, slots=True)
class RelationshipDraft:
    from_canonical: str
    from_type: str
    rel_type: str               # allowlisted relationship type
    to_canonical: str
    to_type: str


@dataclass(frozen=True, slots=True)
class NormalizedRecord:
    connector_id: str
    category: SourceCategory
    url: str                          # canonical URL of the public source
    title: str
    excerpt: str                      # the evidence text (quote / registry summary), unredacted
    statement: str                    # suggested finding statement ("Source X reports …")
    evidence_type: EvidenceType = EvidenceType.TEXT_EXCERPT
    published_at: datetime | None = None
    retrieved_at: datetime | None = None
    publisher: str | None = None
    final_url: str | None = None
    archived_url: str | None = None
    access_status: AccessStatus = AccessStatus.CAPTURED
    entities: tuple[EntityDraft, ...] = ()
    facts: tuple[FactDraft, ...] = ()
    relationships: tuple[RelationshipDraft, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)
    is_lead: bool = False             # transient search-engine lead (not persisted unless captured)
    organization_context: bool = False


@dataclass(frozen=True, slots=True)
class ManualReference:
    """A page the platform will not fetch (login wall, robots, paywall, CAPTCHA)."""

    url: str
    reason: AccessStatus
    note: str


@dataclass(frozen=True, slots=True)
class ConnectorResult:
    records: tuple[NormalizedRecord, ...] = ()
    references: tuple[ManualReference, ...] = ()
    warnings: tuple[str, ...] = ()
    partial: bool = False


@dataclass(frozen=True, slots=True)
class ConnectorInfo:
    id: str
    name: str
    category: SourceCategory
    description: str
    input_types: tuple[InputType, ...]
    docs_url: str
    terms_note: str
    requires_key: str | None = None        # settings attribute holding the key, if any
    key_optional: bool = False
    person_oriented: bool = False          # username/profile lookups — require a recorded purpose
    allowed_in_restricted_mode: bool = False
    min_interval_s: float = 1.0            # politeness: minimum interval between requests per host
