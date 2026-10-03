"""Production refuses to serve a database that still holds the offline demo's public accounts."""

from __future__ import annotations

import pytest
from sqlalchemy import delete, update

from angel_engine.db.models import User
from angel_engine.demo.safety import DemoAccountsPresent, refuse_demo_accounts
from angel_engine.demo.seed import DEMO_USERS

pytestmark = pytest.mark.db


async def test_active_demo_accounts_block_production_start(services):
    email = DEMO_USERS[0].email
    await refuse_demo_accounts(services)  # no demo accounts: nothing to refuse
    async with services.db.session("app") as db:
        db.add(User(email=email, display_name="Demo admin", password_hash="x", role="admin", status="active"))
    try:
        with pytest.raises(DemoAccountsPresent, match="down -v"):
            await refuse_demo_accounts(services)
        async with services.db.session("app") as db:
            await db.execute(update(User).where(User.email == email).values(status="disabled"))
        await refuse_demo_accounts(services)  # disabled demo accounts cannot sign in
    finally:
        async with services.db.session("maintenance") as db:
            await db.execute(delete(User).where(User.email == email))
