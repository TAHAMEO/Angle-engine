"""Application settings (environment variables prefixed ``ANGEL_``; secrets may come from files)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["development", "test", "e2e", "production"]

_DEV_DB = "postgresql+asyncpg://{user}:{user}_dev@127.0.0.1:54329/angel_engine"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ANGEL_",
        env_file=None,
        extra="ignore",
        case_sensitive=False,
    )

    env: Environment = "development"
    app_name: str = "Angel Engine"
    #: Exact browser origin of the web app (scheme://host[:port]); used for CSRF Origin checks.
    public_origin: str = "http://localhost:3000"
    log_level: str = "INFO"
    log_json: bool = False

    # --- Database (separate least-privilege roles) ---------------------------------------------
    database_url: str = _DEV_DB.format(user="ae_app")
    database_url_worker: str = _DEV_DB.format(user="ae_worker")
    database_url_maintenance: str = _DEV_DB.format(user="ae_maintenance")
    database_url_owner: str = _DEV_DB.format(user="ae_owner")
    db_pool_size: int = 10
    db_echo: bool = False

    # --- Redis (rate limiting). None ⇒ in-process limiter (development/test only) -------------
    redis_url: str | None = "redis://127.0.0.1:63799/0"

    # --- Keys -----------------------------------------------------------------------------------
    keyring_path: Path = Path("var/keys/keyring.json")

    # --- Sessions & authentication ------------------------------------------------------------
    session_idle_minutes: int = 30
    session_absolute_hours: int = 12
    max_sessions_per_user: int = 5
    reauth_window_minutes: int = 5
    cookie_secure: bool = True
    mfa_required: bool = True
    registration_open: bool = True  # registration requests still need admin approval
    login_lockout_threshold: int = 5
    login_lockout_minutes: int = 15

    # --- Uploads & image analysis -------------------------------------------------------------
    max_upload_bytes: int = 25 * 1024 * 1024
    image_original_retention_hours: int = 24
    image_original_retention_max_hours: int = 168
    ocr_languages: str = "eng"
    scanner: Literal["clamd", "builtin"] = "clamd"
    clamd_host: str = "127.0.0.1"
    clamd_port: int = 3310
    clamd_socket: str | None = None
    face_detector: Literal["yunet", "fixture"] = "yunet"
    image_sandbox: bool = True
    enable_object_detection: bool = True

    # --- Object storage ------------------------------------------------------------------------
    storage_backend: Literal["local", "s3"] = "local"
    storage_path: Path = Path("var/storage")
    s3_endpoint_url: str | None = None
    s3_bucket: str = "angel-engine"
    s3_region: str = "us-east-1"
    s3_access_key_id: SecretStr | None = None
    s3_secret_access_key: SecretStr | None = None

    # --- AI (Claude) -----------------------------------------------------------------------------
    ai_provider: Literal["anthropic", "fake", "disabled"] = "anthropic"
    anthropic_api_key: SecretStr | None = None
    ai_model: str = "claude-opus-5-5"
    ai_request_timeout_s: float = 300.0
    ai_max_context_documents: int = 120
    ai_daily_token_budget_per_user: int = 2_000_000
    policy_llm_classifier: bool = False

    # --- Connectors ----------------------------------------------------------------------------
    connector_mode: Literal["live", "fixtures"] = "live"
    bot_info_url: str = "https://angel-engine.invalid/bot"
    #: Contact string required by some public APIs (e.g. SEC EDGAR fair-access policy).
    operator_contact: str | None = None
    brave_api_key: SecretStr | None = None
    tineye_api_key: SecretStr | None = None
    google_vision_api_key: SecretStr | None = None
    github_token: SecretStr | None = None
    stackexchange_key: SecretStr | None = None
    disabled_connectors: list[str] = Field(default_factory=list)

    # --- Limits & retention --------------------------------------------------------------------
    rate_limit_enabled: bool = True
    ai_transcript_retention_days: int = 30
    draft_inactive_days: int = 30
    refused_investigation_days: int = 90
    policy_text_retention_days: int = 90
    abuse_report_retention_days: int = 730
    closed_investigation_archive_days: int = 90
    closed_investigation_delete_days: int = 365
    audit_retention_days: int = 730
    export_retention_hours: int = 24

    # --- End-to-end test mode ------------------------------------------------------------------
    e2e_idle_minutes: int | None = None

    @model_validator(mode="after")
    def _production_guardrails(self) -> Settings:
        if self.env == "production":
            problems: list[str] = []
            if self.scanner != "clamd":
                problems.append("ANGEL_SCANNER must be 'clamd' in production")
            if self.face_detector != "yunet":
                problems.append("ANGEL_FACE_DETECTOR must be 'yunet' in production")
            if self.connector_mode != "live":
                problems.append("ANGEL_CONNECTOR_MODE must be 'live' in production")
            if self.ai_provider == "fake":
                problems.append("ANGEL_AI_PROVIDER=fake is not allowed in production")
            if not self.cookie_secure:
                problems.append("ANGEL_COOKIE_SECURE must be true in production")
            if not self.mfa_required:
                problems.append("ANGEL_MFA_REQUIRED must be true in production")
            if self.redis_url is None:
                problems.append("ANGEL_REDIS_URL is required in production")
            if not self.image_sandbox:
                problems.append("ANGEL_IMAGE_SANDBOX must be true in production")
            if self.e2e_idle_minutes is not None:
                problems.append("ANGEL_E2E_IDLE_MINUTES is a test-only setting")
            if problems:
                raise ValueError("; ".join(problems))
        return self

    @property
    def is_production(self) -> bool:
        return self.env == "production"

    @property
    def ai_available(self) -> bool:
        if self.ai_provider == "fake":
            return True
        return self.ai_provider == "anthropic" and self.anthropic_api_key is not None

    @property
    def idle_timeout_minutes(self) -> int:
        if self.env in ("e2e", "test") and self.e2e_idle_minutes:
            return self.e2e_idle_minutes
        return self.session_idle_minutes


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
