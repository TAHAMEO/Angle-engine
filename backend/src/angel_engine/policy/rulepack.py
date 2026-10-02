"""Versioned YAML rule packs: loading (``yaml.safe_load``), validation and condition evaluation."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from angel_engine.policy.annotate import KNOWN_LABELS, Annotations
from angel_engine.policy.normalize import normalize
from angel_engine.policy.types import Category, Decision, Surface

_RULE_ID = re.compile(r"^[A-Z]{2}-\d{3}$")
_VERSION = re.compile(r"^\d{4}\.\d{1,2}\.\d+$")
_RULE_KEYS = frozenset({"id", "category", "strength", "decision", "conditions", "rationale", "notice", "surfaces"})
_GROUP_KEYS = ("all", "any", "none")
STRENGTHS = frozenset({"hard", "soft"})


class RulePackError(ValueError):
    """The rule pack is malformed."""


@dataclass(frozen=True, slots=True)
class LabelTerm:
    labels: frozenset[str]

    def matches(self, ann: Annotations) -> bool:
        return not self.labels.isdisjoint(ann.labels)


@dataclass(frozen=True, slots=True)
class PatternTerm:
    regex: re.Pattern[str]

    def matches(self, ann: Annotations) -> bool:
        return self.regex.search(ann.normalized.text) is not None


@dataclass(frozen=True, slots=True)
class Condition:
    """``all`` must all match, at least one of ``any`` (when given), none of ``none``."""

    all: tuple[Term, ...] = ()
    any: tuple[Term, ...] = ()
    none: tuple[Term, ...] = ()

    def matches(self, ann: Annotations) -> bool:
        if not all(t.matches(ann) for t in self.all):
            return False
        if self.any and not any(t.matches(ann) for t in self.any):
            return False
        return not any(t.matches(ann) for t in self.none)


Term = LabelTerm | PatternTerm | Condition


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    category: Category
    strength: str
    decision: Decision
    condition: Condition
    rationale: str
    notice: str | None = None
    surfaces: frozenset[Surface] | None = None

    @property
    def hard(self) -> bool:
        return self.strength == "hard"

    def applies(self, ann: Annotations, surface: Surface) -> bool:
        if self.surfaces is not None and surface not in self.surfaces:
            return False
        return self.condition.matches(ann)


@dataclass(frozen=True, slots=True)
class RulePack:
    version: str
    rules: tuple[Rule, ...]


def phrase_regex(phrases: Sequence[str]) -> re.Pattern[str]:
    """Compile phrases (normalized like input text; ``*`` = one token) into a word-bounded regex."""
    parts: list[str] = []
    for phrase in phrases:
        normalized = normalize(phrase).text
        if not normalized:
            raise RulePackError(f"empty phrase {phrase!r}")
        tokens = normalized.split(" ")
        parts.append(r"\s+".join(r"\S+" if tok == "*" else re.escape(tok) for tok in tokens))
    parts.sort(key=len, reverse=True)
    return re.compile(r"(?<![\w@])(?:" + "|".join(parts) + r")(?![\w])")


class _Builder:
    def __init__(self, lexicons: Mapping[str, Sequence[str]]) -> None:
        self.lexicons = lexicons
        self._cache: dict[str, re.Pattern[str]] = {}

    def lexicon(self, name: str, where: str) -> re.Pattern[str]:
        if name not in self.lexicons:
            raise RulePackError(f"{where}: unknown lexicon {name!r}")
        if name not in self._cache:
            self._cache[name] = phrase_regex(self.lexicons[name])
        return self._cache[name]

    def term(self, raw: Any, where: str) -> Term:
        if isinstance(raw, str):
            return LabelTerm(frozenset({_label(raw, where)}))
        if not isinstance(raw, Mapping) or len(raw) != 1:
            raise RulePackError(f"{where}: a term must be a label or a single-key mapping")
        key, value = next(iter(raw.items()))
        if key == "labels":
            return LabelTerm(frozenset(_label(v, where) for v in _str_list(value, where)))
        if key == "phrases":
            return PatternTerm(phrase_regex(_str_list(value, where)))
        if key == "lexicon":
            if not isinstance(value, str):
                raise RulePackError(f"{where}: lexicon must be a name")
            return PatternTerm(self.lexicon(value, where))
        if key == "pattern":
            if not isinstance(value, str):
                raise RulePackError(f"{where}: pattern must be a string")
            try:
                return PatternTerm(re.compile(value))
            except re.error as exc:
                raise RulePackError(f"{where}: invalid pattern ({exc})") from exc
        if key in _GROUP_KEYS:
            return self.condition({key: value}, where, nested=True)
        raise RulePackError(f"{where}: unknown term type {key!r}")

    def condition(self, raw: Any, where: str, *, nested: bool = False) -> Condition:
        if not isinstance(raw, Mapping) or not raw or set(raw) - set(_GROUP_KEYS):
            raise RulePackError(f"{where}: conditions must be a mapping with all/any/none")
        groups: dict[str, tuple[Term, ...]] = {}
        for key in _GROUP_KEYS:
            items = raw.get(key, [])
            if not isinstance(items, list):
                raise RulePackError(f"{where}: {key} must be a list")
            groups[key] = tuple(self.term(item, f"{where}.{key}") for item in items)
        if not nested and not groups["all"] and not groups["any"]:
            raise RulePackError(f"{where}: a rule condition needs at least one all/any term")
        if not any(groups.values()):
            raise RulePackError(f"{where}: empty condition group")
        return Condition(all=groups["all"], any=groups["any"], none=groups["none"])


def _label(value: Any, where: str) -> str:
    if not isinstance(value, str) or value not in KNOWN_LABELS:
        raise RulePackError(f"{where}: unknown label {value!r}")
    return value


def _str_list(value: Any, where: str) -> list[str]:
    if not isinstance(value, list) or not value or not all(isinstance(v, str) and v.strip() for v in value):
        raise RulePackError(f"{where}: expected a non-empty list of strings")
    return value


def _enum(enum: type[Category] | type[Decision] | type[Surface], value: Any, where: str) -> Any:
    try:
        return enum(value)
    except ValueError as exc:
        raise RulePackError(f"{where}: invalid value {value!r}") from exc


def parse_rule_pack(source: str) -> RulePack:
    """Parse and validate a rule pack from YAML text."""
    try:
        data = yaml.safe_load(source)
    except yaml.YAMLError as exc:
        raise RulePackError(f"invalid YAML: {exc}") from exc
    if not isinstance(data, Mapping):
        raise RulePackError("rule pack must be a mapping")
    version = data.get("version")
    if not isinstance(version, str) or not _VERSION.match(version):
        raise RulePackError("version must look like YYYY.MM.N")
    lexicons = data.get("lexicons", {})
    if not isinstance(lexicons, Mapping) or not all(isinstance(k, str) for k in lexicons):
        raise RulePackError("lexicons must be a mapping of name -> phrases")
    for name, phrases in lexicons.items():
        _str_list(phrases, f"lexicons.{name}")
    raw_rules = data.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise RulePackError("rules must be a non-empty list")
    builder = _Builder(lexicons)
    rules: list[Rule] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_rules):
        where = f"rules[{index}]"
        if not isinstance(raw, Mapping):
            raise RulePackError(f"{where}: rule must be a mapping")
        unknown = set(raw) - _RULE_KEYS
        if unknown:
            raise RulePackError(f"{where}: unknown keys {sorted(unknown)}")
        rule_id = raw.get("id")
        if not isinstance(rule_id, str) or not _RULE_ID.match(rule_id):
            raise RulePackError(f"{where}: id must look like AB-001")
        if rule_id in seen:
            raise RulePackError(f"{where}: duplicate id {rule_id}")
        seen.add(rule_id)
        where = f"rule {rule_id}"
        strength = raw.get("strength")
        if strength not in STRENGTHS:
            raise RulePackError(f"{where}: strength must be hard or soft")
        rationale = raw.get("rationale")
        if not isinstance(rationale, str) or not rationale.strip():
            raise RulePackError(f"{where}: rationale is required")
        notice = raw.get("notice")
        if notice is not None and (not isinstance(notice, str) or not notice.strip()):
            raise RulePackError(f"{where}: notice must be a non-empty string")
        surfaces_raw = raw.get("surfaces")
        surfaces = None
        if surfaces_raw is not None:
            surfaces = frozenset(_enum(Surface, s, where) for s in _str_list(surfaces_raw, where))
        rules.append(
            Rule(
                id=rule_id,
                category=_enum(Category, raw.get("category"), where),
                strength=strength,
                decision=_enum(Decision, raw.get("decision"), where),
                condition=builder.condition(raw.get("conditions"), f"{where}.conditions"),
                rationale=" ".join(rationale.split()),
                notice=" ".join(notice.split()) if notice else None,
                surfaces=surfaces,
            )
        )
    return RulePack(version=version, rules=tuple(rules))


def load_rule_pack(path: str | Path | None = None) -> RulePack:
    """Load a rule pack from ``path``, or the bundled ``rules/default.yaml`` when omitted."""
    if path is None:
        text = resources.files("angel_engine.policy").joinpath("rules/default.yaml").read_text(encoding="utf-8")
    else:
        text = Path(path).read_text(encoding="utf-8")
    return parse_rule_pack(text)
