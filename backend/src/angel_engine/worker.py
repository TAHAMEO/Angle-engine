"""Worker entry point: ``python -m angel_engine.worker --queues analysis,egress,ai,maintenance``."""

from __future__ import annotations

import argparse
import asyncio

from angel_engine.app_state import build_services
from angel_engine.bootstrap import install_extras
from angel_engine.config import get_settings
from angel_engine.core.logging import configure_logging
from angel_engine.jobs.worker import Worker, install_signal_handlers


async def _main(queues: list[str], concurrency: int) -> None:
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_json)
    services = build_services(settings)
    install_extras(services)
    worker = Worker(services, queues, concurrency=concurrency)
    install_signal_handlers(worker)
    try:
        await worker.run()
    finally:
        await services.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Angel Engine background worker")
    parser.add_argument("--queues", default="analysis,egress,ai,maintenance")
    parser.add_argument("--concurrency", type=int, default=2)
    args = parser.parse_args()
    asyncio.run(_main([q.strip() for q in args.queues.split(",") if q.strip()], args.concurrency))


if __name__ == "__main__":
    main()
