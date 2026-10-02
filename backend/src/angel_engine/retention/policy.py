"""Effective retention policy: deployment defaults (Settings) overridden by admin settings within hard bounds.

Per-investigation overrides (image originals, closed-investigation retention) are applied as
``min(override, platform maximum)`` so an investigation can shorten retention but never extend it.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields, replace
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from angel_engine.config import Settings
from angel_engine.core.problems import ValidationProblem
from angel_engine.db.models import Investigation, Setting

SETTING_KEY = "retention"

#: field -> (minimum, maximum) accepted from administrators.
BOUNDS: dict[str, tuple[int, int]] = {
    "image_original_hours": (0, 168),
    "image_original_max_hours": (0, 168),
    "draft_inactive_days": (1, 365),
    "refused_investigation_days": (1, 365),
    "closed_archive_days": (1, 3650),
    "closed_delete_days": (1, 3650),
    "ai_transcript_days": (1, 180),
    "policy_text_days": (1, 365),
    "audit_days": (365, 2555),
    "abuse_report_days": (30, 2555),
    "export_hours": (1, 168),
}


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    image_original_hours: int
    image_original_max_hours: int
    draft_inactive_days: int
    refused_investigation_days: int
    closed_archive_days: int
    closed_delete_days: int
    ai_transcript_days: int
    policy_text_days: int
    audit_days: int
    abuse_report_days: int
    export_hours: int

    @classmethod
    def defaults(cls, settings: Settings) -> RetentionPolicy:
        return cls(
            image_original_hours=settings.image_original_retention_hours,
            image_original_max_hours=settings.image_original_retention_max_hours,
            draft_inactive_days=settings.draft_inactive_days,
            refused_investigation_days=settings.refused_investigation_days,
            closed_archive_days=settings.closed_investigation_archive_days,
            closed_delete_days=settings.closed_investigation_delete_days,
            ai_transcript_days=settings.ai_transcript_retention_days,
            policy_text_days=settings.policy_text_retention_days,
            audit_days=settings.audit_retention_days,
            abuse_report_days=settings.abuse_report_retention_days,
            export_hours=settings.export_retention_hours,
        )

    def as_dict(self) -> dict[str, int]:
        return asdict(self)

    # -- per-investigation effective values -------------------------------------------------------
    def image_original_hours_for(self, inv: Investigation) -> int:
        hours = inv.image_original_retention_hours
        base = self.image_original_hours if hours is None else hours
        return min(base, self.image_original_max_hours)

    def closed_delete_days_for(self, inv: Investigation) -> int:
        days = inv.closed_retention_days
        return min(days, self.closed_delete_days) if days is not None else self.closed_delete_days


def validate_overrides(values: dict[str, Any]) -> dict[str, int]:
    known = {f.name for f in fields(RetentionPolicy)}
    clean: dict[str, int] = {}
    for key, value in values.items():
        if key not in known:
            raise ValidationProblem(f"Unknown retention setting: {key}.", code="unknown_setting")
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValidationProblem(f"{key} must be an integer.", code="invalid_setting")
        low, high = BOUNDS[key]
        if not low <= value <= high:
            raise ValidationProblem(
                f"{key} must be between {low} and {high}.",
                code="setting_out_of_bounds",
                field=key,
                minimum=low,
                maximum=high,
            )
        clean[key] = value
    return clean


def _apply(base: RetentionPolicy, overrides: dict[str, Any]) -> RetentionPolicy:
    try:
        clean = validate_overrides(overrides)
    except ValidationProblem:
        # A corrupt row must never extend retention: ignore it and fall back to defaults.
        return base
    policy = replace(base, **clean)
    if policy.image_original_hours > policy.image_original_max_hours:
        policy = replace(policy, image_original_hours=policy.image_original_max_hours)
    if policy.closed_archive_days > policy.closed_delete_days:
        policy = replace(policy, closed_archive_days=policy.closed_delete_days)
    return policy


async def stored_overrides(db: AsyncSession) -> dict[str, Any]:
    row = (await db.execute(select(Setting).where(Setting.key == SETTING_KEY))).scalar_one_or_none()
    return dict(row.value) if row is not None else {}


async def load_policy(db: AsyncSession, settings: Settings) -> RetentionPolicy:
    return _apply(RetentionPolicy.defaults(settings), await stored_overrides(db))


def merged(settings: Settings, overrides: dict[str, Any]) -> RetentionPolicy:
    return _apply(RetentionPolicy.defaults(settings), overrides)
