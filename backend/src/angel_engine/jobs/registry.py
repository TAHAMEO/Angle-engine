"""Job handler registry. Handlers are async functions ``(ctx, payload) -> result | None``."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from angel_engine.app_state import Services
from angel_engine.jobs.queue import ClaimedJob

Handler = Callable[["JobContext", dict[str, Any]], Awaitable[dict[str, Any] | None]]
_HANDLERS: dict[str, Handler] = {}


@dataclass
class JobContext:
    services: Services
    job: ClaimedJob
    worker_id: str
    progress_cb: Callable[[dict[str, Any]], Awaitable[None]] | None = field(default=None, repr=False)

    async def progress(self, stage: str, **extra: Any) -> None:
        if self.progress_cb is not None:
            await self.progress_cb({"stage": stage, **extra})


def handler(kind: str) -> Callable[[Handler], Handler]:
    def decorator(fn: Handler) -> Handler:
        if kind in _HANDLERS and _HANDLERS[kind] is not fn:
            raise RuntimeError(f"duplicate job handler for {kind}")
        _HANDLERS[kind] = fn
        return fn

    return decorator


def get_handler(kind: str) -> Handler | None:
    return _HANDLERS.get(kind)


def registered_kinds() -> list[str]:
    return sorted(_HANDLERS)


def load_handlers() -> None:
    """Import every module that registers handlers."""
    import importlib

    for module in ("angel_engine.jobs.maintenance",):
        importlib.import_module(module)
    for optional in (
        "angel_engine.retention.jobs",
        "angel_engine.images.jobs",
        "angel_engine.osint.jobs",
        "angel_engine.ai.jobs",
        "angel_engine.reports.jobs",
        "angel_engine.exports.jobs",
    ):
        try:
            importlib.import_module(optional)
        except ModuleNotFoundError as exc:
            if exc.name != optional:
                raise
