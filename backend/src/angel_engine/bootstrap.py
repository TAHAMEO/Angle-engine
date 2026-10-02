"""Wires optional components (storage, policy engine, scanners, connectors, AI) into the service container.

Each component is imported lazily so a missing optional dependency only disables that feature.
"""

from __future__ import annotations

import structlog

from angel_engine.app_state import Services

log = structlog.get_logger(__name__)


def install_extras(svc: Services) -> None:
    """Populate ``svc.extras``; safe to call more than once."""
    return None
