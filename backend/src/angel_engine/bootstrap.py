"""Wires optional components (storage, policy engine, scanners, connectors, AI) into the service container.

Each component is imported lazily so a missing optional dependency only disables that feature.
"""

from __future__ import annotations

from typing import Any

import structlog

from angel_engine.app_state import Services

log = structlog.get_logger(__name__)


def _storage(svc: Services) -> Any:
    settings = svc.settings
    if settings.storage_backend == "s3":
        from angel_engine.infra.storage.objects import S3ObjectStore

        return S3ObjectStore(
            bucket=settings.s3_bucket,
            endpoint_url=settings.s3_endpoint_url,
            region=settings.s3_region,
            access_key=settings.s3_access_key_id.get_secret_value() if settings.s3_access_key_id else None,
            secret_key=settings.s3_secret_access_key.get_secret_value() if settings.s3_secret_access_key else None,
        )
    from angel_engine.infra.storage.objects import LocalObjectStore

    return LocalObjectStore(settings.storage_path)


def install_extras(svc: Services) -> None:
    """Populate ``svc.extras``; safe to call more than once."""
    if "storage" not in svc.extras:
        svc.extras["storage"] = _storage(svc)
    if "policy" not in svc.extras:
        try:
            from angel_engine.policy import get_default_engine

            svc.extras["policy"] = get_default_engine()
        except ImportError as exc:  # pragma: no cover - only during partial installs
            log.error("policy_engine_unavailable", error_type=type(exc).__name__)
    if "scanner" not in svc.extras:
        try:
            from angel_engine.images.scanning import build_scanner

            svc.extras["scanner"] = build_scanner(svc.settings)
        except ImportError:
            pass
    if "connectors" not in svc.extras:
        from angel_engine.infra.http.robots import RobotsPolicy
        from angel_engine.osint.registry import build_http_client, build_registry

        svc.extras["connectors"] = build_registry(svc.settings)
        http = build_http_client(svc.settings)
        svc.extras["http"] = http
        svc.extras["robots"] = RobotsPolicy(http)
    if "llm" not in svc.extras:
        try:
            from angel_engine.ai.providers import build_provider

            svc.extras["llm"] = build_provider(svc.settings)
        except ImportError:
            pass
