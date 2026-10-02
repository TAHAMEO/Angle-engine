"""Acceptable-use policy engine: refuses doxxing, stalking, tracking and face-identification requests
and suggests lawful alternatives.

>>> from angel_engine.policy import PolicyContext, Surface, get_default_engine
>>> get_default_engine().evaluate("headquarters address of ACME Corp", PolicyContext(Surface.COLLECTION_QUERY)).decision
<Decision.ALLOW: 'allow'>
"""

from __future__ import annotations

from angel_engine.policy.alternatives import alternatives_for
from angel_engine.policy.classifier import ClassifierVerdict, PolicyClassifier
from angel_engine.policy.engine import CLASSIFIER_TIMEOUT_S, RULE_PACK_VERSION, PolicyEngine, get_default_engine
from angel_engine.policy.rulepack import RulePack, RulePackError, load_rule_pack, parse_rule_pack
from angel_engine.policy.types import (
    Alternative,
    Category,
    Decision,
    PolicyContext,
    PolicyResult,
    Surface,
)

__all__ = [
    "CLASSIFIER_TIMEOUT_S",
    "RULE_PACK_VERSION",
    "Alternative",
    "Category",
    "ClassifierVerdict",
    "Decision",
    "PolicyClassifier",
    "PolicyContext",
    "PolicyEngine",
    "PolicyResult",
    "RulePack",
    "RulePackError",
    "Surface",
    "alternatives_for",
    "get_default_engine",
    "load_rule_pack",
    "parse_rule_pack",
]
