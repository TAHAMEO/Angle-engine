"""The acceptable-use policy engine: deterministic rules plus an optional classifier second opinion.

Decision order is allow < warn < review < refuse; the most severe matching rule wins. A classifier
may raise the decision freely, may lower a soft-only result by at most one level (never below
warn), and can never lower a hard rule. Classifier errors and timeouts fall back to the rule
result. Rule evaluation is LRU-cached by (normalized text, context).
"""

from __future__ import annotations

import asyncio
import dataclasses
import functools
import threading
from collections import OrderedDict

from angel_engine.policy.alternatives import alternatives_for
from angel_engine.policy.annotate import annotate
from angel_engine.policy.classifier import ClassifierVerdict, PolicyClassifier
from angel_engine.policy.normalize import normalize
from angel_engine.policy.rulepack import Rule, RulePack, load_rule_pack
from angel_engine.policy.types import Category, Decision, PolicyContext, PolicyResult

RULE_PACK_VERSION = "2026.10.0"
CLASSIFIER_TIMEOUT_S = 3.0
_ALLOW_RATIONALE = "No acceptable-use concerns were found."
_BY_SEVERITY = {d.severity: d for d in Decision}
_CATEGORY_LABELS = {c: c.value.replace("_", " ") for c in Category}


def _unique(items: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(i for i in items if i))


class PolicyEngine:
    """Evaluate text against a rule pack. Thread-safe; cheap to call repeatedly."""

    def __init__(
        self,
        rule_pack: RulePack | None = None,
        *,
        cache_size: int = 2048,
        classifier_timeout: float = CLASSIFIER_TIMEOUT_S,
    ) -> None:
        self.rule_pack = rule_pack or load_rule_pack()
        self.classifier_timeout = classifier_timeout
        self._cache_size = cache_size
        self._cache: OrderedDict[tuple[str, PolicyContext], tuple[PolicyResult, bool]] = OrderedDict()
        self._lock = threading.Lock()
        self.cache_hits = 0
        self.cache_misses = 0

    @property
    def rule_pack_version(self) -> str:
        return self.rule_pack.version

    # ------------------------------------------------------------------------------ rules
    def evaluate(self, text: str, ctx: PolicyContext) -> PolicyResult:
        """Deterministic rule evaluation (no classifier)."""
        result, _ = self._evaluate_rules(text, ctx)
        return result

    def _evaluate_rules(self, text: str, ctx: PolicyContext) -> tuple[PolicyResult, bool]:
        nt = normalize(text)
        key = (nt.cased, ctx)
        with self._lock:
            cached = self._cache.get(key)
            if cached is not None:
                self._cache.move_to_end(key)
                self.cache_hits += 1
        if cached is None:
            ann = annotate(nt, ctx)
            matched = [rule for rule in self.rule_pack.rules if rule.applies(ann, ctx.surface)]
            cached = self._build(matched)
            with self._lock:
                self.cache_misses += 1
                self._cache[key] = cached
                if len(self._cache) > self._cache_size:
                    self._cache.popitem(last=False)
        result, hard = cached
        return dataclasses.replace(result, details=dict(result.details)), hard

    def _build(self, matched: list[Rule]) -> tuple[PolicyResult, bool]:
        version = self.rule_pack.version
        if not matched:
            return (
                PolicyResult(
                    decision=Decision.ALLOW,
                    rationale=_ALLOW_RATIONALE,
                    rule_pack_version=version,
                    details={"hard": "false", "matched_rules": "0"},
                ),
                False,
            )
        top = max(rule.decision.severity for rule in matched)
        final = [rule for rule in matched if rule.decision.severity == top]
        decision = _BY_SEVERITY[top]
        categories = tuple(dict.fromkeys(rule.category for rule in final))
        hard = any(rule.hard for rule in final)
        result = PolicyResult(
            decision=decision,
            categories=categories,
            rule_ids=tuple(rule.id for rule in matched),
            rationale=final[0].rationale,
            alternatives=alternatives_for(categories) if decision is not Decision.ALLOW else (),
            notices=_unique([rule.notice or "" for rule in final]),
            rule_pack_version=version,
            details={"hard": str(hard).lower(), "matched_rules": str(len(matched))},
        )
        return result, hard

    # ------------------------------------------------------------------------------ classifier
    async def evaluate_with_classifier(
        self, text: str, ctx: PolicyContext, classifier: PolicyClassifier | None
    ) -> PolicyResult:
        """Rule evaluation combined with an optional classifier (``asyncio.wait_for`` timeout)."""
        base, hard = self._evaluate_rules(text, ctx)
        if classifier is None:
            base.details["classifier"] = "not_configured"
            return base
        try:
            verdict = await asyncio.wait_for(classifier.classify(text, ctx), timeout=self.classifier_timeout)
        except TimeoutError:
            base.details["classifier"] = "timeout"
            return base
        except Exception as exc:  # any classifier failure falls back to the deterministic result
            base.details["classifier"] = f"error:{type(exc).__name__}"
            return base
        if verdict is None:
            base.details["classifier"] = "abstained"
            return base
        return combine(base, hard, verdict)


def combine(base: PolicyResult, hard: bool, verdict: ClassifierVerdict) -> PolicyResult:
    """Merge a rule result with a classifier verdict according to the raise/lower limits."""
    rule_level, model_level = base.decision.severity, verdict.decision.severity
    details = {**base.details, "classifier": "applied"}
    if model_level > rule_level:
        decision = verdict.decision
        categories = tuple(dict.fromkeys(verdict.categories or base.categories))
        labels = ", ".join(_CATEGORY_LABELS[c] for c in categories) or "an acceptable-use concern"
        return dataclasses.replace(
            base,
            decision=decision,
            categories=categories,
            rationale=f"An additional automated review identified a likely acceptable-use concern ({labels}).",
            alternatives=alternatives_for(categories) if decision is not Decision.ALLOW else (),
            llm_decision=verdict.decision,
            details={**details, "classifier_effect": "raised"},
        )
    if model_level < rule_level and not hard and rule_level > Decision.WARN.severity:
        lowered = max(rule_level - 1, model_level, Decision.WARN.severity)
        decision = _BY_SEVERITY[lowered]
        return dataclasses.replace(
            base,
            decision=decision,
            rationale=(
                f"{base.rationale} An additional automated review assessed the request as lower risk, "
                "so the decision was lowered by one level."
            ),
            alternatives=alternatives_for(base.categories),
            llm_decision=verdict.decision,
            details={**details, "classifier_effect": "lowered"},
        )
    return dataclasses.replace(base, llm_decision=verdict.decision, details={**details, "classifier_effect": "none"})


@functools.cache
def get_default_engine() -> PolicyEngine:
    """The process-wide engine using the bundled rule pack."""
    engine = PolicyEngine(load_rule_pack())
    if engine.rule_pack_version != RULE_PACK_VERSION:
        raise RuntimeError("bundled rule pack version does not match RULE_PACK_VERSION")
    return engine
