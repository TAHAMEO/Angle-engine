"""Production safety net for the offline demo's public credentials."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import select

from angel_engine.db.models import User
from angel_engine.demo.seed import DEMO_USERS

if TYPE_CHECKING:
    from angel_engine.app_state import Services


class DemoAccountsPresent(RuntimeError):
    """The database still holds active demo accounts, whose password and TOTP secrets are published."""


async def refuse_demo_accounts(svc: Services) -> None:
    """Stop a production server from accepting the demo accounts, e.g. after switching a demo database to production."""
    emails = [user.email for user in DEMO_USERS]
    async with svc.db.session("app") as db:
        found = (
            (await db.execute(select(User.email).where(User.email.in_(emails), User.status != "disabled")))
            .scalars()
            .all()
        )
    if found:
        raise DemoAccountsPresent(
            f"{len(found)} offline-demo account(s) with public passwords and TOTP secrets are active in this database. "
            "Production mode refuses to start. Remove the demo data (docker compose -f deploy/docker-compose.yml "
            "-f deploy/docker-compose.demo.yml down -v) or disable these accounts first."
        )
