"""Gated public-occurrence providers for images (egress worker): TinEye and Google Cloud Vision.

They only ever receive the bytes of the sanitized preview (faces and sensitive text masked, re-encoded without
metadata) — never an original — and only after :func:`angel_engine.images.service.search_gate` allowed the
search. Google Vision is asked for logos, landmarks and web matches only: the face feature is never requested,
and "web entities" and "best guess" labels (which can name people) are discarded, as are landmark coordinates.
Visually similar images are dropped when faces or people were detected. Results are *reports by the provider*:
they become source-reported evidence or AI-hypothesis clues, never facts.
"""

from __future__ import annotations

import base64
import json
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol
from urllib.parse import urlencode

from angel_engine.config import Settings
from angel_engine.infra.http.safe_client import HttpResult, SafeHttpClient
from angel_engine.osint.connectors.base import parse_date

MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_MATCHES = 30
_TAGS = re.compile(r"<[^>]{0,200}>")


class ProviderError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class OccurrenceMatch:
    page_url: str
    match_type: str  # "matching_copy" | "exact" | "partial" | "similar"
    image_url: str | None = None
    crawl_date: datetime | None = None
    page_title: str | None = None
    score: float | None = None


@dataclass(frozen=True, slots=True)
class VisualLabel:
    kind: str  # "brand" | "landmark"
    name: str
    score: float


@dataclass(slots=True)
class OccurrenceResult:
    provider: str
    matches: list[OccurrenceMatch] = field(default_factory=list)
    labels: list[VisualLabel] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class OccurrenceProvider(Protocol):
    id: str
    name: str
    key_setting: str

    async def search(
        self, preview: bytes, http: SafeHttpClient, settings: Settings, *, allow_similar: bool
    ) -> OccurrenceResult: ...


def _key(settings: Settings, attribute: str) -> str:
    value = getattr(settings, attribute, None)
    if value is None:
        raise ProviderError("needs_key")
    return str(value.get_secret_value())


def _json(result: HttpResult) -> Any:
    if result.status in (401, 403):
        raise ProviderError("access_denied")
    if result.status == 429:
        raise ProviderError("rate_limited")
    if result.status == 402:
        raise ProviderError("quota_exhausted")
    if not result.ok:
        raise ProviderError("upstream_error")
    try:
        return json.loads(result.content)
    except ValueError as exc:
        raise ProviderError("invalid_response") from exc


def _clean_title(value: Any) -> str | None:
    if not value:
        return None
    text = " ".join(_TAGS.sub("", str(value)).split())
    return text[:300] or None


class TinEye:
    """TinEye reverse image search (fingerprint matching; prepaid search bundles)."""

    id = "tineye"
    name = "TinEye"
    key_setting = "tineye_api_key"
    endpoint = "https://api.tineye.com/rest/search/"

    async def search(
        self, preview: bytes, http: SafeHttpClient, settings: Settings, *, allow_similar: bool
    ) -> OccurrenceResult:
        boundary = secrets.token_hex(16)
        body = (
            (
                f'--{boundary}\r\nContent-Disposition: form-data; name="image_upload"; filename="preview.jpg"\r\n'
                "Content-Type: image/jpeg\r\n\r\n"
            ).encode()
            + preview
            + f"\r\n--{boundary}--\r\n".encode()
        )
        params = urlencode({"limit": MAX_MATCHES, "backlink_limit": 5, "sort": "crawl_date", "order": "asc"})
        result = await http.post(
            f"{self.endpoint}?{params}",
            content=body,
            content_type=f"multipart/form-data; boundary={boundary}",
            headers={"x-api-key": _key(settings, self.key_setting)},
            max_bytes=MAX_RESPONSE_BYTES,
            min_interval=1.0,
        )
        data = _json(result)
        out = OccurrenceResult(self.id)
        for match in ((data.get("results") or {}).get("matches") or [])[:MAX_MATCHES]:
            score = match.get("score")
            for backlink in (match.get("backlinks") or [])[:5]:
                page = backlink.get("backlink") or backlink.get("url")
                if not page:
                    continue
                out.matches.append(
                    OccurrenceMatch(
                        page_url=str(page),
                        match_type="matching_copy",
                        image_url=backlink.get("url"),
                        crawl_date=parse_date(backlink.get("crawl_date")),
                        score=float(score) if isinstance(score, int | float) else None,
                    )
                )
        return out


class GoogleVision:
    """Google Cloud Vision: logo and landmark detection plus web matches (never the face feature)."""

    id = "google_vision"
    name = "Google Cloud Vision"
    key_setting = "google_vision_api_key"
    endpoint = "https://vision.googleapis.com/v1/images:annotate"
    #: The only features ever requested.
    features = ("LOGO_DETECTION", "LANDMARK_DETECTION", "WEB_DETECTION")

    async def search(
        self, preview: bytes, http: SafeHttpClient, settings: Settings, *, allow_similar: bool
    ) -> OccurrenceResult:
        request = {
            "requests": [
                {
                    "image": {"content": base64.b64encode(preview).decode()},
                    "features": [{"type": f, "maxResults": 20} for f in self.features],
                    "imageContext": {"webDetectionParams": {"includeGeoResults": False}},
                }
            ]
        }
        result = await http.post(
            self.endpoint,
            content=json.dumps(request).encode(),
            content_type="application/json",
            headers={"x-goog-api-key": _key(settings, self.key_setting)},
            max_bytes=MAX_RESPONSE_BYTES,
            min_interval=1.0,
        )
        data = _json(result)
        responses = data.get("responses") or [{}]
        response = responses[0] if isinstance(responses[0], dict) else {}
        if response.get("error"):
            raise ProviderError("upstream_error")
        out = OccurrenceResult(self.id)
        for kind, key in (("brand", "logoAnnotations"), ("landmark", "landmarkAnnotations")):
            for annotation in (response.get(key) or [])[:10]:
                name = " ".join(str(annotation.get("description") or "").split())[:200]
                if name:
                    out.labels.append(VisualLabel(kind, name, float(annotation.get("score") or 0.0)))
        web = response.get("webDetection") or {}
        for page in (web.get("pagesWithMatchingImages") or [])[:MAX_MATCHES]:
            if not page.get("url"):
                continue
            full, partial = page.get("fullMatchingImages") or [], page.get("partialMatchingImages") or []
            first = (full or partial or [{}])[0]
            out.matches.append(
                OccurrenceMatch(
                    page_url=str(page["url"]),
                    match_type="exact" if full else "partial",
                    image_url=first.get("url"),
                    page_title=_clean_title(page.get("pageTitle")),
                )
            )
        if allow_similar:
            for image in (web.get("visuallySimilarImages") or [])[:10]:
                if image.get("url"):
                    out.matches.append(OccurrenceMatch(page_url=str(image["url"]), match_type="similar",
                                                       image_url=str(image["url"])))  # fmt: skip
        elif web.get("visuallySimilarImages"):
            out.warnings.append("Visually similar images were not kept because faces or people were detected.")
        # webEntities and bestGuessLabels are deliberately never read: they can name people.
        return out


PROVIDERS: dict[str, OccurrenceProvider] = {p.id: p for p in (TinEye(), GoogleVision())}


def provider_status(settings: Settings, provider_id: str) -> tuple[str, str | None]:
    provider = PROVIDERS.get(provider_id)
    if provider is None:
        return "unknown", "Unknown provider."
    if provider_id in settings.disabled_connectors:
        return "disabled", "Disabled by the administrator."
    if getattr(settings, provider.key_setting, None) is None:
        return "needs_key", f"Configure ANGEL_{provider.key_setting.upper()} to enable {provider.name}."
    return "ready", None


__all__ = [
    "PROVIDERS",
    "GoogleVision",
    "OccurrenceMatch",
    "OccurrenceProvider",
    "OccurrenceResult",
    "ProviderError",
    "TinEye",
    "VisualLabel",
    "provider_status",
]
