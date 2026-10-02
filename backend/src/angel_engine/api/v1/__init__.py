"""Version 1 of the REST API."""

from __future__ import annotations

from fastapi import APIRouter

from angel_engine.api.v1.routers import (
    abuse,
    admin,
    assistant,
    audit,
    auth,
    collection,
    dashboard,
    evidence,
    findings,
    graph,
    health,
    images,
    investigations,
    legal,
    me,
    notes,
    policy,
    search,
    security,
    sources,
    timeline,
)


def build_router() -> APIRouter:
    api = APIRouter(prefix="/api/v1")
    for module in (
        health, auth, me, legal, admin, audit, abuse, security, policy, search,
        investigations, dashboard, collection, sources, evidence, findings, graph, timeline, notes, images,
        assistant,
    ):  # fmt: skip
        api.include_router(module.router)
    return api
