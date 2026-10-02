"""Public contract of the sensitive-data guard.

Everything that enters Angel Engine from the outside world (OCR text, web captures, registry
records, image metadata, AI output, user notes) passes through :func:`angel_engine.guard.redact_text`
*before* it is encrypted, tokenized for search, stored or displayed. Only the redacted text and
per-type counts are ever persisted — never the raw sensitive values.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class RedactionMode(StrEnum):
    """Strictness level.

    ``standard`` is used for ordinary investigations. ``restricted`` is used for investigations whose
    subject is an individual: every email address, phone number and street address is removed,
    including organizational ones.
    """

    STANDARD = "standard"
    RESTRICTED = "restricted"


class SourceKind(StrEnum):
    """Where the text came from. Organization-address exemptions only apply to registry/government."""

    OCR = "ocr"
    WEB = "web"
    REGISTRY = "registry"          # company registries (GLEIF, SEC, …)
    GOVERNMENT = "government"      # official government publications
    METADATA = "metadata"          # EXIF/XMP/IPTC free-text fields
    AI_OUTPUT = "ai_output"
    USER_NOTE = "user_note"
    QUERY = "query"


class RedactionKind(StrEnum):
    PAYMENT_CARD = "payment_card"
    BANK_ACCOUNT = "bank_account"            # IBAN and similar
    NATIONAL_ID = "national_id"              # SSN, NINO, SIN, …
    PASSPORT = "passport"                    # passport numbers in context, MRZ lines
    CREDENTIAL = "credential"                # passwords, API keys, tokens, JWTs, private keys
    STREET_ADDRESS = "street_address"
    EMAIL = "email"
    PHONE = "phone"
    DATE_OF_BIRTH = "date_of_birth"
    VEHICLE_PLATE = "vehicle_plate"
    PRECISE_COORDINATES = "precise_coordinates"
    URL_SECRET = "url_secret"                # userinfo / token query parameters inside URLs
    WIFI_CREDENTIAL = "wifi_credential"      # WIFI:S:...;P:...; QR payloads


class SensitivityFlag(StrEnum):
    """Content that is *flagged* (hidden by default, excluded from AI context) rather than redacted."""

    MEDICAL = "medical"


@dataclass(frozen=True, slots=True)
class RedactionContext:
    source_kind: SourceKind = SourceKind.WEB
    #: True when the surrounding record is about an organization (e.g. a registry record or an
    #: organization's contact page). Enables keeping role mailboxes and registered office addresses.
    organization_context: bool = False


@dataclass(frozen=True, slots=True)
class RedactionSpan:
    """A redacted region of the *input* text (character offsets into the original string)."""

    start: int
    end: int
    kind: RedactionKind
    replacement: str


@dataclass(frozen=True, slots=True)
class RedactionResult:
    text: str                                   # redacted text, safe to store/display
    counts: dict[str, int] = field(default_factory=dict)   # RedactionKind value -> count
    spans: tuple[RedactionSpan, ...] = ()       # offsets into the original input (for OCR box masking)
    flags: frozenset[SensitivityFlag] = frozenset()

    @property
    def redacted(self) -> bool:
        return bool(self.counts)
