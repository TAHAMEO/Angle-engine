"""Domain enumerations shared by models, services and API schemas."""

from __future__ import annotations

from enum import StrEnum


def values(enum: type[StrEnum]) -> tuple[str, ...]:
    return tuple(m.value for m in enum)


class Role(StrEnum):
    ADMIN = "admin"
    SUPERVISOR = "supervisor"
    INVESTIGATOR = "investigator"
    VIEWER = "viewer"
    AUDITOR = "auditor"


class UserStatus(StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    DISABLED = "disabled"


class SessionState(StrEnum):
    MFA_PENDING = "mfa_pending"
    MFA_ENROLL = "mfa_enroll"
    ACTIVE = "active"


class MemberRole(StrEnum):
    OWNER = "owner"
    EDITOR = "editor"
    VIEWER = "viewer"


class InvestigationStatus(StrEnum):
    DRAFT = "draft"
    PENDING_REVIEW = "pending_review"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    CLOSED = "closed"
    ARCHIVED = "archived"
    REFUSED = "refused"
    DELETED = "deleted"


class SubjectType(StrEnum):
    ORGANIZATION = "organization"
    WEBSITE = "website"
    PUBLIC_EVENT = "public_event"
    PUBLIC_FIGURE_ROLE = "public_figure_role"
    INDIVIDUAL = "individual"
    IMAGE_PROVENANCE = "image_provenance"
    OTHER = "other"


class PurposeCategory(StrEnum):
    JOURNALISM = "journalism"
    FACT_CHECKING = "fact_checking"
    DUE_DILIGENCE = "due_diligence"
    BRAND_PROTECTION = "brand_protection"
    CYBERSECURITY = "cybersecurity"
    ACADEMIC_RESEARCH = "academic_research"
    LEGAL_PROCEEDINGS = "legal_proceedings"
    LAW_ENFORCEMENT = "law_enforcement"
    MISINFORMATION_RESEARCH = "misinformation_research"
    IMAGE_VERIFICATION = "image_verification"
    OTHER = "other"


class LawfulBasis(StrEnum):
    LEGITIMATE_INTEREST = "legitimate_interest"
    PUBLIC_INTEREST_JOURNALISM = "public_interest_journalism"
    LEGAL_OBLIGATION = "legal_obligation"
    LAW_ENFORCEMENT_AUTHORIZATION = "law_enforcement_authorization"
    RESEARCH_EXEMPTION = "research_exemption"
    CONTRACT = "contract"
    CONSENT = "consent"
    OTHER = "other"


class Provenance(StrEnum):
    OBSERVED = "observed"
    SOURCE_REPORTED = "source_reported"
    ANALYST_INFERENCE = "analyst_inference"
    AI_HYPOTHESIS = "ai_hypothesis"


class VerificationStatus(StrEnum):
    CONFIRMED_BY_SOURCE = "confirmed_by_source"
    CORROBORATED = "corroborated"
    UNVERIFIED = "unverified"
    CONTRADICTED = "contradicted"
    AI_HYPOTHESIS = "ai_hypothesis"


class Confidence(StrEnum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"


class Stance(StrEnum):
    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"
    CONTEXT = "context"


class FindingCategory(StrEnum):
    """The eleven public-source categories plus image analysis and analyst/AI analysis."""

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
    IMAGE_ANALYSIS = "image_analysis"
    ANALYSIS = "analysis"


class EntityType(StrEnum):
    IMAGE = "image"
    USERNAME = "username"
    WEBSITE = "website"
    DOMAIN = "domain"
    WEBPAGE = "webpage"
    ORGANIZATION = "organization"
    EVENT = "event"
    DOCUMENT = "document"
    LOCATION = "location"
    BRAND = "brand"
    PRODUCT = "product"
    LANDMARK = "landmark"
    PUBLIC_FIGURE = "public_figure"


#: Entity types whose names are intrinsically public and may be stored in plaintext for search.
PLAINTEXT_ENTITY_TYPES = (
    EntityType.ORGANIZATION,
    EntityType.WEBSITE,
    EntityType.DOMAIN,
    EntityType.BRAND,
    EntityType.PRODUCT,
    EntityType.LANDMARK,
    EntityType.EVENT,
    EntityType.LOCATION,
)


class RelationshipType(StrEnum):
    SHOWS_TEXT = "shows_text"
    LINKS_TO = "links_to"
    HOSTED_ON = "hosted_on"
    OPERATED_BY = "operated_by"
    SUBSIDIARY_OF = "subsidiary_of"
    MENTIONS = "mentions"
    PUBLISHED_BY = "published_by"
    PARTICIPATED_IN = "participated_in"
    LOCATED_IN = "located_in"
    SAME_IMAGE_AS = "same_image_as"
    SIMILAR_IMAGE_TO = "similar_image_to"
    DOCUMENTED_BY = "documented_by"
    REGISTERED_BY = "registered_by"
    DEPICTS = "depicts"  # non-biometric only: landmarks, signs, logos, objects


class ImageStatus(StrEnum):
    UPLOADED = "uploaded"
    SCANNING = "scanning"
    CLEAN = "clean"
    INFECTED = "infected"
    QUARANTINED = "quarantined"
    SCAN_FAILED = "scan_failed"
    ANALYZING = "analyzing"
    ANALYZED = "analyzed"
    ANALYSIS_FAILED = "analysis_failed"
    ORIGINAL_PURGED = "original_purged"
    FILES_DELETED = "files_deleted"


class JobQueue(StrEnum):
    ANALYSIS = "analysis"
    EGRESS = "egress"
    AI = "ai"
    MAINTENANCE = "maintenance"


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    DEAD = "dead"
    CANCELLED = "cancelled"


class PolicyDecisionValue(StrEnum):
    ALLOW = "allow"
    WARN = "warn"
    REVIEW = "review"
    REFUSE = "refuse"


class AbuseCategory(StrEnum):
    TARGETED_BY_INVESTIGATION = "targeted_by_investigation"
    PLATFORM_MISUSE = "platform_misuse"
    DATA_REMOVAL_REQUEST = "data_removal_request"
    SECURITY_VULNERABILITY = "security_vulnerability"
    INACCURATE_INFORMATION = "inaccurate_information"
    OTHER = "other"


class AbuseStatus(StrEnum):
    NEW = "new"
    TRIAGING = "triaging"
    ACTIONED = "actioned"
    DISMISSED = "dismissed"


class LegalDocumentKind(StrEnum):
    TERMS = "terms"
    PRIVACY = "privacy"
    ACCEPTABLE_USE = "acceptable_use"
    RESPONSIBLE_USE = "responsible_use"
