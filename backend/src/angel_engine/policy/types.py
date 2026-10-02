"""Public contract of the acceptable-use policy engine.

The engine screens investigation purposes, every collection query, assistant prompts, AI-suggested
queries, image notes and custom report sections. It never sees or returns personal data beyond the
text it is asked to evaluate, and refusals always carry lawful alternatives.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Decision(StrEnum):
    ALLOW = "allow"
    WARN = "warn"  # allowed, with a notice the user must acknowledge
    REVIEW = "review"  # requires supervisor approval before it runs
    REFUSE = "refuse"

    @property
    def severity(self) -> int:
        return _SEVERITY[self]


_SEVERITY = {Decision.ALLOW: 0, Decision.WARN: 1, Decision.REVIEW: 2, Decision.REFUSE: 3}


class Category(StrEnum):
    HOME_ADDRESS = "home_address"
    LOCATION_TRACKING = "location_tracking"
    FACIAL_IDENTIFICATION = "facial_identification"
    PRIVATE_CONTACT_INFO = "private_contact_info"
    PRIVATE_PERSONAL_DATA = "private_personal_data"  # DOB, home town, family, health of a person
    HARASSMENT_STALKING = "harassment_stalking"
    DOXXING = "doxxing"
    PRIVACY_CIRCUMVENTION = "privacy_circumvention"
    LEAKED_OR_RESTRICTED_DATA = "leaked_or_restricted_data"
    TARGETED_SURVEILLANCE = "targeted_surveillance"
    SENSITIVE_ATTRIBUTE_INFERENCE = "sensitive_attribute_inference"
    IMPERSONATION = "impersonation"
    INDIVIDUAL_SUBJECT = "individual_subject"  # review: research focused on a person
    BROAD_LOCATION_ONLY = "broad_location_only"  # warn: location requests are broad-level only


class Surface(StrEnum):
    INVESTIGATION_PURPOSE = "investigation_purpose"
    COLLECTION_QUERY = "collection_query"
    ASSISTANT_PROMPT = "assistant_prompt"
    AI_SUGGESTED_QUERY = "ai_suggested_query"
    IMAGE_NOTE = "image_note"
    NOTE = "note"
    REPORT_SECTION = "report_section"


@dataclass(frozen=True, slots=True)
class PolicyContext:
    surface: Surface
    #: investigation subject type: organization|website|public_event|public_figure_role|individual|
    #: image_provenance|other (None when not yet known, e.g. during the wizard preflight)
    subject_type: str | None = None
    restricted_mode: bool = False
    face_count: int = 0
    person_count: int = 0


@dataclass(frozen=True, slots=True)
class Alternative:
    kind: str  # "query" | "connector" | "guidance"
    label: str
    template: str | None = None
    connector_id: str | None = None


@dataclass(frozen=True, slots=True)
class PolicyResult:
    decision: Decision
    categories: tuple[Category, ...] = ()
    rule_ids: tuple[str, ...] = ()
    rationale: str = ""
    alternatives: tuple[Alternative, ...] = ()
    notices: tuple[str, ...] = ()
    rule_pack_version: str = ""
    llm_decision: Decision | None = None
    details: dict[str, str] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.decision in (Decision.ALLOW, Decision.WARN)
