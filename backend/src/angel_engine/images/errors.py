"""Typed errors of the image pipeline.

Messages and codes are fixed strings chosen by the pipeline: they never contain file content,
metadata values, OCR text or exception text coming from a decoder.
"""

from __future__ import annotations

from angel_engine.images.types import StageStatus

#: Rejections caused by policy (format/size limits) rather than by a damaged file.
POLICY_REASONS = frozenset(
    {
        "too_large",
        "unsupported_format",
        "svg_not_allowed",
        "heif_disabled",
        "avif_not_supported",
        "bigtiff_not_supported",
        "mime_mismatch",
        "dimensions_exceeded",
    }
)


class ImageRejected(Exception):
    """The upload is refused. ``reason_code`` is stable and safe to show to the uploader."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.message = message

    @property
    def status(self) -> StageStatus:
        return StageStatus.POLICY_BLOCKED if self.reason_code in POLICY_REASONS else StageStatus.FAILED

    def __repr__(self) -> str:
        return f"ImageRejected({self.reason_code!r}, {self.message!r})"


class AnalyzerError(Exception):
    """An analyzer failed with a stable error code (never a decoder message)."""

    def __init__(self, code: str, status: StageStatus = StageStatus.FAILED) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


class StageSkipped(Exception):
    """An optional analyzer did not run (missing model/binary, disabled by configuration)."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ModelUnavailable(AnalyzerError):
    def __init__(self) -> None:
        super().__init__("model_missing")


class ModelIntegrityError(AnalyzerError):
    def __init__(self) -> None:
        super().__init__("model_checksum_mismatch")


class PreviewRefused(AnalyzerError):
    """The sanitized preview cannot be built because a mandatory privacy stage did not succeed."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
