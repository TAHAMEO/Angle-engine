"""Acceptable-use policy engine: table-driven cases (tests/policy/cases.yaml) plus unit tests."""

from __future__ import annotations

import asyncio
import pathlib
from typing import Any

import pytest
import yaml

from angel_engine.policy import (
    CLASSIFIER_TIMEOUT_S,
    RULE_PACK_VERSION,
    Category,
    ClassifierVerdict,
    Decision,
    PolicyClassifier,
    PolicyContext,
    PolicyEngine,
    RulePackError,
    Surface,
    alternatives_for,
    get_default_engine,
    load_rule_pack,
    parse_rule_pack,
)
from angel_engine.policy.annotate import KNOWN_LABELS, annotate
from angel_engine.policy.normalize import fold_leet, normalize

CASES_FILE = pathlib.Path(__file__).resolve().parents[1] / "policy" / "cases.yaml"
CASES: list[dict[str, Any]] = yaml.safe_load(CASES_FILE.read_text(encoding="utf-8"))
Q = Surface.COLLECTION_QUERY


def _ctx(case: dict[str, Any]) -> PolicyContext:
    return PolicyContext(surface=Surface(case.get("surface", "collection_query")), **case.get("context", {}))


def _labels(text: str, **ctx: Any) -> frozenset[str]:
    return annotate(normalize(text), PolicyContext(surface=ctx.pop("surface", Q), **ctx)).labels


# ---------------------------------------------------------------------------- table-driven cases


def test_case_file_shape() -> None:
    ids = [c["id"] for c in CASES]
    assert len(CASES) >= 70
    assert len(ids) == len(set(ids))
    assert sum(i.startswith("D") and i[1:3].isdigit() for i in ids) >= 29  # D01–D28 (+ D18a/D18b)


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_policy_case(case: dict[str, Any]) -> None:
    result = get_default_engine().evaluate(case["input"], _ctx(case))
    expected = case["expect"] if isinstance(case["expect"], list) else [case["expect"]]
    assert result.decision.value in expected, (result.decision, result.rule_ids)
    got = {c.value for c in result.categories}
    assert set(case.get("categories", [])) <= got, (got, result.rule_ids)
    if case.get("categories_any"):
        assert got & set(case["categories_any"]), got
    assert result.rule_pack_version == RULE_PACK_VERSION
    if result.decision is Decision.REFUSE:
        assert len(result.alternatives) >= 2
        assert result.rationale
        assert case["input"].strip().lower() not in result.rationale.lower()


def test_rationales_never_echo_user_text() -> None:
    engine = get_default_engine()
    for case in CASES:
        result = engine.evaluate(case["input"], _ctx(case))
        text = " ".join([result.rationale, *result.notices, *(a.label for a in result.alternatives)])
        for name in ("Jane", "Doe", "Smith", "Taylor", "Swift", "leaks_guy", "Northwind"):
            if name in case["input"]:
                assert name not in text, (case["id"], name)


@pytest.mark.parametrize(
    ("title", "purpose", "description", "subject_type", "allowed"),
    [
        (
            "Northwind storefront photo verification",
            "Verify the publication history and provenance of a viral photo of the Northwind Coffee Roasters "
            "storefront before it is used in a fact-checking article.",
            "Public sources only.",
            "organization",
            {Decision.ALLOW, Decision.WARN},
        ),
        (
            "Northwind storefront photo verification",
            "Verify the publication history and provenance of a viral photo of the Northwind Coffee Roasters "
            "storefront before it is used in a fact-checking article.",
            None,
            "organization",
            {Decision.ALLOW, Decision.WARN},
        ),
        (
            "Spokesperson statement verification",
            "Verify statements a company spokesperson made in public press conferences about the product recall, "
            "using official releases and published news coverage only.",
            None,
            "individual",
            {Decision.ALLOW, Decision.WARN, Decision.REVIEW},
        ),
        (
            "Director due diligence",
            "Review public, official-capacity statements and registry filings of a company director for a "
            "due-diligence report requested by our compliance team.",
            None,
            "individual",
            {Decision.ALLOW, Decision.WARN, Decision.REVIEW},
        ),
    ],
)
def test_investigation_purposes_not_refused(
    title: str, purpose: str, description: str | None, subject_type: str, allowed: set[Decision]
) -> None:
    text = "\n\n".join(part for part in (title, purpose, description) if part)
    ctx = PolicyContext(surface=Surface.INVESTIGATION_PURPOSE, subject_type=subject_type)
    assert get_default_engine().evaluate(text, ctx).decision in allowed


@pytest.mark.parametrize("subject_type", ["individual", "organization", None])
def test_stalking_purpose_refused(subject_type: str | None) -> None:
    text = (
        "Ex check\n\nFind the home address of my ex-girlfriend Jane Doe and track where she goes every day so I "
        "can show up there."
    )
    result = get_default_engine().evaluate(
        text, PolicyContext(surface=Surface.INVESTIGATION_PURPOSE, subject_type=subject_type)
    )
    assert result.decision is Decision.REFUSE
    assert {Category.HOME_ADDRESS, Category.LOCATION_TRACKING, Category.HARASSMENT_STALKING} & set(result.categories)
    assert result.alternatives


def test_individual_subject_type_is_reviewed_on_purpose_surface() -> None:
    ctx = PolicyContext(surface=Surface.INVESTIGATION_PURPOSE, subject_type="individual")
    result = get_default_engine().evaluate("Verify public statements made at a press conference.", ctx)
    assert result.decision is Decision.REVIEW
    assert result.categories == (Category.INDIVIDUAL_SUBJECT,)
    assert result.notices


def test_broad_location_notice() -> None:
    result = get_default_engine().evaluate("where was this photo taken?", PolicyContext(Surface.IMAGE_NOTE))
    assert result.decision is Decision.WARN
    assert "Location analysis is limited to broad, public-level places." in result.notices


# ---------------------------------------------------------------------------- normalization


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("h\U0000200bome addr\U00000435ss", "home address"),  # zero-width + Cyrillic e
        ("\U0000202etrack\U0000202c her", "track her"),  # bidi controls
        ("\U0001d421\U0001d428\U0001d426\U0001d41e", "home"),  # mathematical bold
        ("\U0000ff48\U0000ff4f\U0000ff4d\U0000ff45", "home"),  # fullwidth
        ("tr4ck h3r l0cation", "track her location"),  # digits inside words
        ("1ocation", "location"),  # edge digit, known word
        ("pa$$word em@il", "password email"),  # inner symbols
        ("Jane\U00002019s  \t HOME\n\naddress", "jane's home address"),  # quotes, case, whitespace
        ("li\U00000301ve", "live"),  # combining accent
        ("w\U000003bfman", "woman"),  # Greek omicron
    ],
)
def test_normalize(raw: str, expected: str) -> None:
    assert normalize(raw).text == expected


@pytest.mark.parametrize("word", ["covid19", "web3", "4chan", "b2b", "mp3", "2024", "x86"])
def test_leet_folding_keeps_ordinary_alphanumerics(word: str) -> None:
    assert fold_leet(word) == word


def test_normalize_tokens_and_offsets() -> None:
    nt = normalize("Is   Jane Doe's e-mail jane@acme.example or @jdoe on acme.example?")
    assert all(nt.text[t.start : t.end] == t.text for t in nt.tokens)
    kinds = {t.text: t.kind for t in nt.tokens}
    assert kinds["jane@acme.example"] == "email"
    assert kinds["@jdoe"] == "handle"
    assert kinds["acme.example"] == "domain"
    assert kinds["'s"] == "poss"
    assert [t.cased for t in nt.tokens][1:3] == ["Jane", "Doe"]
    assert nt.cased == "Is Jane Doe's e-mail jane@acme.example or @jdoe on acme.example?"


# ---------------------------------------------------------------------------- annotation


def test_annotate_attachment_org_vs_person() -> None:
    org = _labels("phone number of the city council office")
    assert "data:contact@org" in org and "data:contact@person" not in org
    person = _labels("John Smith's personal cell number")
    assert {"data:contact@person", "data:contact_personal", "subject:named"} <= person


def test_annotate_benign_track_senses_are_suppressed() -> None:
    for text in ("track changes to the policy", "ACME CEO's track record", "track the spread of the image"):
        assert "intent:track" not in _labels(text), text
    assert "intent:track" in _labels("track her every day")


def test_annotate_subjects() -> None:
    labels = _labels("Does ACME know where Jane Doe works?")
    assert {"subject:org", "subject:named", "subject:person"} <= labels
    assert "subject:public_role" in _labels("is the mayor here")
    assert "subject:relational" in _labels("my ex-girlfriend")
    assert "subject:relational" not in _labels("our partners at ACME")  # business sense needs "my"


def test_annotate_chained_data_and_intent_objects() -> None:
    labels = _labels("what is his date of birth and home town?")
    assert "data:personal_details@person" in labels
    assert "intent:monitor@relational" in _labels("alert me whenever my ex posts")
    assert "intent:find@relational" not in _labels("my boss asked me to find ACME's filings")


def test_annotate_context_labels() -> None:
    labels = _labels("anything", surface=Surface.IMAGE_NOTE, face_count=2, person_count=1, restricted_mode=True)
    assert {"ctx:faces", "ctx:persons", "ctx:restricted", "ctx:surface:image_note", "ctx:subject:unknown"} <= labels
    assert "ctx:subject:individual" in _labels("x", subject_type="individual")


def test_known_labels_cover_relations_and_context() -> None:
    assert {"data:home_address@relational", "intent:monitor@person", "ctx:surface:note", "face:biometric"} <= (
        KNOWN_LABELS
    )


# ---------------------------------------------------------------------------- rule pack


def test_default_rule_pack() -> None:
    pack = load_rule_pack()
    assert pack.version == RULE_PACK_VERSION
    ids = [r.id for r in pack.rules]
    assert len(ids) == len(set(ids))
    assert {r.category for r in pack.rules} == set(Category)
    assert all(r.rationale for r in pack.rules)
    assert get_default_engine() is get_default_engine()
    assert get_default_engine().rule_pack_version == RULE_PACK_VERSION


_RULE = """
version: "2026.1.0"
rules:
  - id: XX-001
    category: doxxing
    strength: hard
    decision: refuse
    rationale: test
    conditions:
      {conditions}
"""


@pytest.mark.parametrize(
    ("conditions", "message"),
    [
        ("any: [intent:nope]", "unknown label"),
        ("any: [{lexicon: missing}]", "unknown lexicon"),
        ("any: [{pattern: '(unclosed'}]", "invalid pattern"),
        ("none: [intent:find]", "at least one all/any"),
        ("any: [{bogus: 1}]", "unknown term"),
    ],
)
def test_rule_pack_validation_errors(conditions: str, message: str) -> None:
    with pytest.raises(RulePackError, match=message):
        parse_rule_pack(_RULE.format(conditions=conditions))


@pytest.mark.parametrize(
    ("source", "message"),
    [
        ("version: 1\nrules: []", "version"),
        ('version: "2026.1.0"\nrules: []', "non-empty"),
        (_RULE.format(conditions="any: [intent:find]").replace("doxxing", "nonsense"), "invalid value"),
        (_RULE.format(conditions="any: [intent:find]").replace("hard", "medium"), "strength"),
        (
            _RULE.format(conditions="any: [intent:find]") + _RULE.split("rules:\n")[1].format(conditions="any: [x:y]"),
            "duplicate|unknown label",
        ),
        ("- not a mapping", "mapping"),
    ],
)
def test_rule_pack_structure_errors(source: str, message: str) -> None:
    with pytest.raises(RulePackError, match=message):
        parse_rule_pack(source)


def test_phrase_terms_and_nested_groups() -> None:
    pack = parse_rule_pack(
        """
version: "2026.1.0"
lexicons:
  benign: [press release, "who * this company"]
rules:
  - id: TS-001
    category: targeted_surveillance
    strength: soft
    decision: review
    rationale: test
    conditions:
      all: [intent:monitor]
      none:
        - lexicon: benign
        - all: [subject:org, {none: [subject:person]}]
"""
    )
    engine = PolicyEngine(pack)
    assert engine.evaluate("monitor her posts", PolicyContext(Q)).decision is Decision.REVIEW
    assert engine.evaluate("monitor the press release feed", PolicyContext(Q)).decision is Decision.ALLOW
    assert engine.evaluate("monitor who runs this company", PolicyContext(Q)).decision is Decision.ALLOW
    assert engine.evaluate("monitor ACME", PolicyContext(Q)).decision is Decision.ALLOW


# ---------------------------------------------------------------------------- engine behaviour


def test_cache_hits_and_evasion_share_entries() -> None:
    engine = PolicyEngine()
    ctx = PolicyContext(Q)
    first = engine.evaluate("track her location", ctx)
    engine.evaluate("track her location", ctx)
    engine.evaluate("track  her\N{NO-BREAK SPACE}location", ctx)  # same normalized form
    assert engine.cache_misses == 1 and engine.cache_hits == 2
    first.details["mutated"] = "yes"
    assert "mutated" not in engine.evaluate("track her location", ctx).details
    engine.evaluate("track her location", PolicyContext(Q, face_count=1))
    assert engine.cache_misses == 2


def test_empty_text_is_allowed() -> None:
    result = get_default_engine().evaluate("", PolicyContext(Q))
    assert result.decision is Decision.ALLOW and result.allowed


def test_alternatives_for_refusal_categories() -> None:
    for category in Category:
        alts = alternatives_for([category])
        assert len(alts) >= 2, category
    assert any(a.connector_id == "gleif" for a in alternatives_for([Category.HOME_ADDRESS]))
    assert any(a.connector_id == "sec_edgar" for a in alternatives_for([Category.HOME_ADDRESS]))
    assert any(a.connector_id == "wayback" for a in alternatives_for([Category.PRIVACY_CIRCUMVENTION]))
    assert any("Acceptable Use Policy" in a.label for a in alternatives_for([Category.DOXXING]))
    assert len(alternatives_for([])) >= 2
    combined = alternatives_for([Category.HOME_ADDRESS, Category.HOME_ADDRESS, Category.DOXXING])
    assert len(combined) == len(set(combined))


# ---------------------------------------------------------------------------- classifier combination

_COMBINATION_PACK = """
version: "2026.1.0"
rules:
  - id: HA-001
    category: home_address
    strength: hard
    decision: refuse
    rationale: Hard refusal.
    conditions: {any: [data:home_address]}
  - id: TS-001
    category: targeted_surveillance
    strength: soft
    decision: refuse
    rationale: Soft refusal.
    conditions: {any: [intent:monitor]}
  - id: IS-001
    category: individual_subject
    strength: soft
    decision: review
    rationale: Soft review.
    conditions: {any: [intent:research]}
  - id: BL-001
    category: broad_location_only
    strength: soft
    decision: warn
    rationale: Soft warning.
    conditions: {any: [photo:where_taken]}
"""


class FakeClassifier:
    def __init__(self, verdict: ClassifierVerdict | None = None, *, delay: float = 0.0, error: bool = False) -> None:
        self.verdict = verdict
        self.delay = delay
        self.error = error
        self.calls = 0

    async def classify(self, text: str, ctx: PolicyContext) -> ClassifierVerdict | None:
        self.calls += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.error:
            raise RuntimeError("classifier unavailable")
        return self.verdict


@pytest.fixture
def combo_engine() -> PolicyEngine:
    return PolicyEngine(parse_rule_pack(_COMBINATION_PACK), classifier_timeout=0.05)


def _verdict(decision: Decision, *categories: Category) -> FakeClassifier:
    return FakeClassifier(ClassifierVerdict(decision=decision, categories=categories, rationale="model says so"))


def test_fake_classifier_satisfies_protocol() -> None:
    assert isinstance(FakeClassifier(), PolicyClassifier)
    assert CLASSIFIER_TIMEOUT_S == 3.0


@pytest.mark.parametrize(
    ("text", "model", "expected"),
    [
        ("monitor her posts", Decision.ALLOW, Decision.REVIEW),  # soft refuse lowered one level only
        ("monitor her posts", Decision.WARN, Decision.REVIEW),
        ("research ACME", Decision.ALLOW, Decision.WARN),  # soft review -> warn
        ("where was this photo taken", Decision.ALLOW, Decision.WARN),  # never below warn
        ("her home address", Decision.ALLOW, Decision.REFUSE),  # hard rules cannot be lowered
        ("research ACME", Decision.REFUSE, Decision.REFUSE),  # raising is free
        ("an ordinary question", Decision.REVIEW, Decision.REVIEW),
        ("an ordinary question", Decision.ALLOW, Decision.ALLOW),
    ],
)
async def test_classifier_limits(combo_engine: PolicyEngine, text: str, model: Decision, expected: Decision) -> None:
    classifier = _verdict(model, Category.DOXXING) if model.severity >= Decision.REVIEW.severity else _verdict(model)
    result = await combo_engine.evaluate_with_classifier(text, PolicyContext(Q), classifier)
    assert result.decision is expected
    assert result.llm_decision is model
    assert result.details["classifier"] == "applied"
    assert result.rule_pack_version == "2026.1.0"


async def test_classifier_raise_uses_its_categories_and_calm_rationale(combo_engine: PolicyEngine) -> None:
    classifier = _verdict(Decision.REFUSE, Category.DOXXING)
    result = await combo_engine.evaluate_with_classifier("who is Jane Doe really", PolicyContext(Q), classifier)
    assert result.decision is Decision.REFUSE
    assert result.categories == (Category.DOXXING,)
    assert len(result.alternatives) >= 2
    assert "Jane" not in result.rationale and "model says so" not in result.rationale


async def test_classifier_timeout_falls_back(combo_engine: PolicyEngine) -> None:
    classifier = FakeClassifier(ClassifierVerdict(Decision.REFUSE), delay=1.0)
    result = await combo_engine.evaluate_with_classifier("monitor her posts", PolicyContext(Q), classifier)
    assert result.decision is Decision.REFUSE
    assert result.llm_decision is None
    assert result.details["classifier"] == "timeout"
    allowed = await combo_engine.evaluate_with_classifier("an ordinary question", PolicyContext(Q), classifier)
    assert allowed.decision is Decision.ALLOW and allowed.llm_decision is None


async def test_classifier_error_and_abstention_fall_back(combo_engine: PolicyEngine) -> None:
    ctx = PolicyContext(Q)
    errored = await combo_engine.evaluate_with_classifier("research ACME", ctx, FakeClassifier(error=True))
    assert errored.decision is Decision.REVIEW and errored.details["classifier"] == "error:RuntimeError"
    abstained = await combo_engine.evaluate_with_classifier("research ACME", ctx, FakeClassifier(None))
    assert abstained.decision is Decision.REVIEW and abstained.details["classifier"] == "abstained"
    unconfigured = await combo_engine.evaluate_with_classifier("research ACME", ctx, None)
    assert unconfigured.decision is Decision.REVIEW and unconfigured.details["classifier"] == "not_configured"


async def test_default_engine_with_classifier_matches_sync_rules() -> None:
    engine = get_default_engine()
    ctx = PolicyContext(Surface.INVESTIGATION_PURPOSE, subject_type="organization")
    sync = engine.evaluate("research John Smith", ctx)
    async_result = await engine.evaluate_with_classifier("research John Smith", ctx, None)
    assert (sync.decision, sync.categories, sync.rule_ids) == (
        async_result.decision,
        async_result.categories,
        async_result.rule_ids,
    )
