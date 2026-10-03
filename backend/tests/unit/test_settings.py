"""Settings: production guardrails, secret files and blank values."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from angel_engine.config import Settings


def test_blank_api_keys_mean_not_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANGEL_ANTHROPIC_API_KEY", "")
    monkeypatch.setenv("ANGEL_BRAVE_API_KEY", "   ")
    settings = Settings(ai_provider="anthropic")
    assert settings.anthropic_api_key is None and settings.brave_api_key is None
    assert settings.ai_available is False


def test_secret_files_are_read(tmp_path: Path) -> None:
    (tmp_path / "angel_database_url").write_text("postgresql+asyncpg://ae_app:pw@db:5432/angel_engine\n")
    (tmp_path / "angel_anthropic_api_key").write_text("test-key-value")
    settings = Settings(_secrets_dir=tmp_path)  # type: ignore[call-arg]
    assert settings.database_url == "postgresql+asyncpg://ae_app:pw@db:5432/angel_engine"
    assert settings.anthropic_api_key is not None
    assert settings.anthropic_api_key.get_secret_value() == "test-key-value"


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"scanner": "builtin"}, "ANGEL_SCANNER"),
        ({"connector_mode": "fixtures"}, "ANGEL_CONNECTOR_MODE"),
        ({"ai_provider": "fake"}, "ANGEL_AI_PROVIDER"),
        ({"cookie_secure": False}, "ANGEL_COOKIE_SECURE"),
        ({"face_detector": "fixture"}, "ANGEL_FACE_DETECTOR"),
        ({"redis_url": None}, "ANGEL_REDIS_URL"),
    ],
)
def test_production_refuses_development_shortcuts(override: dict[str, object], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        Settings(env="production", **override)  # type: ignore[arg-type]
