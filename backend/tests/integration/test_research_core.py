"""Research-engine core: sources, evidence, findings + verification transitions, entities, graph, timeline."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from angel_engine.core.problems import ConflictState, Forbidden, ValidationProblem
from angel_engine.db.models import Finding, FindingStatusHistory, Investigation, Relationship
from angel_engine.db.session import set_investigation_scope
from angel_engine.entities.service import EntityInput, canonicalize, upsert_entity
from angel_engine.evidence.service import EvidenceInput, SourceInput, add_evidence, upsert_source
from angel_engine.findings import service as findings
from angel_engine.findings.service import FindingInput, LinkInput, TransitionRequest
from angel_engine.graph import service as graph
from angel_engine.graph.service import RelationshipInput
from angel_engine.timeline.service import EventInput, create_event
from tests.factories import make_investigation
from tests.helpers import create_user

pytestmark = pytest.mark.db
JUSTIFICATION = "The company's own registry filing states this directly."


async def _ctx(services, *, subject_type: str = "organization"):  # type: ignore[no-untyped-def]
    owner = await create_user(services)
    inv_id = await make_investigation(services, owner.id, subject_type=subject_type,
                                      status="active")
    return owner, inv_id


async def _source(db, cipher, inv, url: str, category: str = "news_articles", **kw):  # type: ignore[no-untyped-def]
    return (await upsert_source(db, cipher, inv, SourceInput(url=url, category=category, connector_id="test",
                                                             **kw))).source


async def _evidence(db, cipher, inv, source, excerpt: str):  # type: ignore[no-untyped-def]
    return (await add_evidence(db, cipher, inv, EvidenceInput(excerpt=excerpt, evidence_type="text_excerpt",
                                                              provenance="source_reported",
                                                              source_id=source.id))).item


async def _open(services, inv_id):  # type: ignore[no-untyped-def]
    db_cm = services.db.session("app")
    db = await db_cm.__aenter__()
    await set_investigation_scope(db, [inv_id])
    inv = await db.get(Investigation, inv_id)
    cipher = await services.vault.investigation_cipher(db, inv_id)
    return db_cm, db, inv, cipher


async def test_sources_are_normalized_and_deduplicated(services):
    _, inv_id = await _ctx(services)
    cm, db, inv, cipher = await _open(services, inv_id)
    try:
        first = await upsert_source(db, cipher, inv, SourceInput(
            url="https://News.Example.org/story?id=7&utm_source=feed#top", category="news_articles",
            connector_id="gdelt", title="Northwind opens second roastery"))
        again = await upsert_source(db, cipher, inv, SourceInput(
            url="https://news.example.org/story?fbclid=abc&id=7", category="news_articles", connector_id="gdelt"))
        assert first.created and not again.created and again.source.id == first.source.id
        assert first.source.label_seq == 1 and first.source.registrable_domain == "example.org"
        assert b"news.example.org" not in first.source.url  # URL encrypted at rest
        assert first.source.title_tokens  # blind-indexed title
    finally:
        await cm.__aexit__(None, None, None)


async def test_evidence_is_redacted_deduplicated_and_immutable(services):
    _, inv_id = await _ctx(services)
    cm, db, inv, cipher = await _open(services, inv_id)
    try:
        src = await _source(db, cipher, inv, "https://northwind-coffee.example/about")
        added = await add_evidence(db, cipher, inv, EvidenceInput(
            excerpt="Founded in 2016. Questions? Write to jane87@gmail.com or info@northwind-coffee.example.",
            evidence_type="page_capture", provenance="observed", source_id=src.id))
        assert added.created and added.item.redaction_counts.get("email") == 1
        stored = cipher.open(added.item.excerpt, table="evidence_items", column="excerpt", row_id=added.item.id)
        assert "jane87@gmail.com" not in stored and "info@northwind-coffee.example" in stored
        dup = await add_evidence(db, cipher, inv, EvidenceInput(
            excerpt="Founded in 2016. Questions? Write to jane87@gmail.com or info@northwind-coffee.example.",
            evidence_type="page_capture", provenance="observed", source_id=src.id))
        assert not dup.created and dup.item.id == added.item.id
        with pytest.raises(ValueError):
            await add_evidence(db, cipher, inv, EvidenceInput(excerpt="x", evidence_type="text_excerpt",
                                                              provenance="ai_hypothesis", source_id=src.id))
        await db.flush()
        with pytest.raises(DBAPIError, match="immutable"):
            async with db.begin_nested():
                await db.execute(text("UPDATE evidence_items SET captured_at = now() - interval '1 day' "
                                      "WHERE id = :i"), {"i": added.item.id})
    finally:
        await cm.__aexit__(None, None, None)


async def test_finding_transitions_follow_evidence_rules(services):
    owner, inv_id = await _ctx(services)
    cm, db, inv, cipher = await _open(services, inv_id)
    try:
        registry = await _source(db, cipher, inv, "https://registry.example.gov/company/123",
                                 category="public_company_information")
        news = await _source(db, cipher, inv, "https://news.example.org/northwind")
        same_publisher = await _source(db, cipher, inv, "https://www.example.org/business/northwind")
        e1 = await _evidence(db, cipher, inv, registry, "Northwind Coffee Roasters was incorporated in 2016.")
        e2 = await _evidence(db, cipher, inv, news, "The roastery, founded in 2016, opened a second site.")
        e3 = await _evidence(db, cipher, inv, same_publisher, "Northwind (est. 2016) roasts in Lisbon.")

        with pytest.raises(ValidationProblem):
            await findings.create_finding(db, cipher, inv, FindingInput(
                statement="Founded in 2016", category="public_company_information", provenance="source_reported"))
        finding = await findings.create_finding(db, cipher, inv, FindingInput(
            statement="Northwind Coffee Roasters was founded in 2016.", category="public_company_information",
            provenance="source_reported", created_by=owner.id,
            links=(LinkInput(e2.id), LinkInput(e3.id))))
        assert finding.verification_status == "unverified" and finding.label_seq == 1

        # Status changes outside the transition service are blocked by a trigger.
        with pytest.raises(DBAPIError, match="audited transition"):
            async with db.begin_nested():
                await db.execute(text("UPDATE findings SET verification_status = 'corroborated' WHERE id = :i"),
                                 {"i": finding.id})

        links = await findings.load_links(db, finding.id)
        result = findings.evaluate(finding, links, restricted_mode=False, actor_role="investigator",
                                   actor_id=owner.id)
        assert "confirmed_by_source" in result.failed  # no link directly states the claim yet
        assert "corroborated" in result.failed  # news.example.org and www.example.org share one publisher
        assert result.snapshot["independent_origins"] == 1
        with pytest.raises(ConflictState) as excinfo:
            await findings.transition(db, cipher, inv, finding,
                                      TransitionRequest("confirmed_by_source", JUSTIFICATION, (e2.id,)),
                                      actor_id=owner.id, actor_role="investigator")
        assert excinfo.value.extra["failed_preconditions"]

        await findings.add_links(db, inv, finding, [LinkInput(e1.id, directly_states=True)], owner.id)
        with pytest.raises(ValidationProblem):  # cited evidence must be linked to the finding
            await findings.transition(db, cipher, inv, finding,
                                      TransitionRequest("confirmed_by_source", JUSTIFICATION, (e1.id, e1.id, uuid4())),
                                      actor_id=owner.id, actor_role="investigator")
        with pytest.raises(ValidationProblem):  # justification too short
            await findings.transition(db, cipher, inv, finding, TransitionRequest("confirmed_by_source", "ok", (e1.id,)),
                                      actor_id=owner.id, actor_role="investigator")
        previous = await findings.transition(db, cipher, inv, finding,
                                             TransitionRequest("confirmed_by_source", JUSTIFICATION, (e1.id,)),
                                             actor_id=owner.id, actor_role="investigator")
        assert previous == "unverified" and finding.verification_status == "confirmed_by_source"

        # Corroboration needs two independent origins plus an attestation.
        corroborate = TransitionRequest("corroborated", JUSTIFICATION, (e1.id, e2.id))
        with pytest.raises(ValidationProblem, match="independent"):
            await findings.transition(db, cipher, inv, finding, corroborate, actor_id=owner.id,
                                      actor_role="investigator")
        await findings.transition(db, cipher, inv, finding,
                                  TransitionRequest("corroborated", JUSTIFICATION, (e1.id, e2.id), True),
                                  actor_id=owner.id, actor_role="investigator")
        assert finding.verification_status == "corroborated"

        # A contradicting link blocks promotions; contradicted needs it; dismissing it auto-downgrades.
        contra_src = await _source(db, cipher, inv, "https://other-news.example.net/northwind")
        e4 = await _evidence(db, cipher, inv, contra_src, "Northwind Coffee Roasters was founded in 2014.")
        await findings.add_links(db, inv, finding, [LinkInput(e4.id, stance="contradicts")], owner.id)
        await findings.transition(db, cipher, inv, finding,
                                  TransitionRequest("contradicted", "A national newspaper reports a 2014 founding.",
                                                    (e4.id,)), actor_id=owner.id, actor_role="investigator")
        contra_link = next(li.link for li in await findings.load_links(db, finding.id)
                           if li.link.stance == "contradicts")
        downgraded = await findings.dismiss_link(db, cipher, inv, finding, contra_link.id,
                                                 "The 2014 date refers to the founder's first market stall.",
                                                 owner.id)
        assert downgraded == "unverified" and finding.verification_status == "unverified"

        history = (await db.execute(select(FindingStatusHistory).where(
            FindingStatusHistory.finding_id == finding.id).order_by(FindingStatusHistory.created_at))).scalars().all()
        assert [h.to_status for h in history] == ["unverified", "confirmed_by_source", "corroborated", "contradicted",
                                                  "unverified"]
        assert history[-1].automatic and history[1].justification is not None
        with pytest.raises(DBAPIError, match="append-only"):
            async with db.begin_nested():
                await db.execute(text("DELETE FROM finding_status_history WHERE id = :i"), {"i": history[0].id})
    finally:
        await cm.__aexit__(None, None, None)


async def test_ai_hypothesis_status_only_for_ai_findings(services):
    owner, inv_id = await _ctx(services)
    cm, db, inv, cipher = await _open(services, inv_id)
    try:
        src = await _source(db, cipher, inv, "https://northwind-coffee.example/")
        ev = await _evidence(db, cipher, inv, src, "Fresh roasts daily on Harbour Street.")
        observed = await findings.create_finding(db, cipher, inv, FindingInput(
            statement="The shop advertises daily roasting.", category="websites", provenance="observed",
            links=(LinkInput(ev.id),)))
        with pytest.raises(ConflictState):
            await findings.transition(db, cipher, inv, observed,
                                      TransitionRequest("ai_hypothesis", JUSTIFICATION), actor_id=owner.id,
                                      actor_role="investigator")
        ai = await findings.create_finding(db, cipher, inv, FindingInput(
            statement="The storefront may be in Lisbon's Baixa district.", category="analysis",
            provenance="ai_hypothesis"))
        assert ai.verification_status == "ai_hypothesis"
    finally:
        await cm.__aexit__(None, None, None)


async def test_restricted_mode_promotions_need_a_second_supervisor(services):
    owner, inv_id = await _ctx(services, subject_type="individual")
    supervisor = await create_user(services, role="supervisor")
    cm, db, inv, cipher = await _open(services, inv_id)
    try:
        assert inv.restricted_mode
        src = await _source(db, cipher, inv, "https://press.example.com/statement")
        ev = await _evidence(db, cipher, inv, src, "The spokesperson confirmed the recall on 3 March.")
        finding = await findings.create_finding(db, cipher, inv, FindingInput(
            statement="The recall was confirmed publicly on 3 March.", category="news_articles",
            provenance="source_reported", created_by=owner.id, links=(LinkInput(ev.id, directly_states=True),)))
        req = TransitionRequest("confirmed_by_source", JUSTIFICATION, (ev.id,))
        with pytest.raises(Forbidden):
            await findings.transition(db, cipher, inv, finding, req, actor_id=owner.id, actor_role="investigator")
        await findings.transition(db, cipher, inv, finding, req, actor_id=supervisor.id, actor_role="supervisor")
        assert finding.verification_status == "confirmed_by_source"
    finally:
        await cm.__aexit__(None, None, None)


async def test_entities_graph_and_timeline(services):
    owner, inv_id = await _ctx(services)
    cm, db, inv, cipher = await _open(services, inv_id)
    try:
        src = await _source(db, cipher, inv, "https://rdap.example.net/domain/northwind-coffee.example",
                            category="public_directories")
        ev = await _evidence(db, cipher, inv, src, "Registrar: Example Registrar Ltd. Registered 2016-03-02.")
        org, created = await upsert_entity(db, cipher, inv, EntityInput("organization", "Northwind Coffee Roasters Lda"))
        same, again = await upsert_entity(db, cipher, inv, EntityInput("organization", "northwind coffee roasters"))
        assert created and not again and same.id == org.id
        assert canonicalize("username", "@NorthwindRoasters", {"platform": "mastodon"}) == "mastodon:northwindroasters"
        domain, _ = await upsert_entity(db, cipher, inv, EntityInput("domain", "www.Northwind-Coffee.example"))
        assert domain.name == "www.Northwind-Coffee.example"
        with pytest.raises(ValidationProblem):
            await upsert_entity(db, cipher, inv, EntityInput("public_figure", "Ana Example"))
        with pytest.raises(ValidationProblem):
            await upsert_entity(db, cipher, inv, EntityInput("organization", "Contact jane87@gmail.com"))
        with pytest.raises(ValidationProblem):
            await upsert_entity(db, cipher, inv, EntityInput("location", "Lisbon"))  # needs a level

        with pytest.raises(ValidationProblem):
            await graph.upsert_relationship(db, inv, RelationshipInput(org.id, "registered_by", domain.id, (ev.id,)))
        rel, created = await graph.upsert_relationship(
            db, inv, RelationshipInput(domain.id, "operated_by", org.id, (ev.id,), created_by=owner.id))
        assert created and rel.verification_status == "unverified"
        city, _ = await upsert_entity(db, cipher, inv, EntityInput("location", "Lisbon", location_level="locality",
                                                                   country="PT"))
        rel2, _ = await graph.upsert_relationship(db, inv, RelationshipInput(org.id, "located_in", city.id, (ev.id,)))
        sub = await graph.subgraph(db, cipher, inv, root=domain.id, depth=2)
        assert {n["name"] for n in sub["nodes"]} >= {"Northwind Coffee Roasters Lda", "Lisbon"}
        edge = next(e for e in sub["edges"] if e["id"] == str(rel.id))
        assert edge["supporting_count"] == 1 and edge["evidence"][0]["source_label"] == "S-1"
        assert await graph.shortest_path(db, inv, domain.id, city.id) == [rel.id, rel2.id]

        await graph.transition(db, cipher, rel, "confirmed_by_source", JUSTIFICATION, (ev.id,), actor_id=owner.id,
                               independence_attested=False)
        assert rel.verification_status == "confirmed_by_source"
        assert await graph.unlink_evidence(db, rel2, ev.id) is True  # last support gone ⇒ edge removed
        assert (await db.execute(select(Relationship.id).where(Relationship.id == rel2.id))).first() is None

        with pytest.raises(ValidationProblem):
            await create_event(db, cipher, inv, EventInput(datetime(2016, 3, 2, tzinfo=UTC), "day", "registration",
                                                           "Domain registered", ()))
        event = await create_event(db, cipher, inv, EventInput(
            datetime(2016, 3, 2, tzinfo=UTC), "day", "registration", "Domain northwind-coffee.example registered",
            (ev.id,), created_by=owner.id))
        assert event.verification_status == "unverified"
        stored = (await db.execute(select(Finding).where(Finding.investigation_id == inv.id))).first()
        assert stored is None
    finally:
        await cm.__aexit__(None, None, None)
