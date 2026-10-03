"""The demo seed never adds its published accounts to a database that already belongs to a real installation."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from angel_engine.db.models import User
from angel_engine.demo import seed
from tests.helpers import create_user

pytestmark = pytest.mark.db


async def test_seed_leaves_a_real_installation_alone(services, settings, monkeypatch, capsys):
    await create_user(services, role="admin")
    monkeypatch.setattr(seed, "get_settings", lambda: settings)
    with pytest.raises(SystemExit) as refused:
        await seed.run_seed()
    assert refused.value.code == 2
    assert "real installation" in capsys.readouterr().err
    async with services.db.session("app") as db:
        demo = select(User.id).where(User.email.in_([user.email for user in seed.DEMO_USERS]))
        assert (await db.execute(demo)).first() is None
