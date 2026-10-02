"""Version 1 of the REST API."""

from __future__ import annotations

from fastapi import APIRouter

from angel_engine.api.v1.routers import (
    abuse,
    admin,
    audit,
    auth,
    health,
    investigations,
    legal,
    me,
    policy,
    security,
)


def build_router() -> APIRouter:
    api = APIRouter(prefix="/api/v1")
    for module in (health, auth, me, legal, admin, audit, abuse, security, policy, investigations):
        api.include_router(module.router)
    return api
