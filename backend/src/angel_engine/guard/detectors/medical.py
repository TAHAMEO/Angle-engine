"""Health information about a person: a medical term in the same sentence as a personal reference.

Standard mode only *flags* the text (:attr:`SensitivityFlag.MEDICAL`); restricted mode replaces the
whole sentence with ``[REDACTED:medical]``. Organizational statements ("the hospital opened a
cancer ward") contain no personal reference and are not flagged.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from angel_engine.guard.detectors.base import P_MEDICAL, Detection, Scan, detection, trie_pattern, words
from angel_engine.guard.types import RedactionKind, SensitivityFlag

_TERMS = (
    "diagnosis",
    "diagnoses",
    "diagnosed",
    "diagnose",
    "hiv",
    "cancer",
    "tumor",
    "tumors",
    "tumour",
    "tumours",
    "chemo",
    "chemotherapy",
    "radiotherapy",
    "pregnant",
    "pregnancy",
    "miscarriage",
    "depression",
    "depressive",
    "anxiety disorder",
    "panic disorder",
    "bipolar",
    "schizophrenia",
    "schizophrenic",
    "rehab",
    "overdose",
    "overdosed",
    "prescription",
    "prescriptions",
    "prescribed",
    "medication",
    "medications",
    "disability",
    "disabilities",
    "therapy session",
    "therapy sessions",
    "in therapy",
    "psychiatric",
    "psychiatrist",
    "mental health",
    "mental illness",
    "abortion",
    "dementia",
    "alzheimer",
    "alzheimers",
    "alzheimer's",
    "autism",
    "autistic",
    "adhd",
    "ptsd",
    "epilepsy",
    "epileptic",
    "diabetes",
    "diabetic",
    "hepatitis",
    "dialysis",
    "transplant",
    "addiction",
    "alcoholism",
    "eating disorder",
    "anorexia",
    "anorexic",
    "bulimia",
    "bulimic",
    "suicidal",
    "suicide attempt",
    "self-harm",
    "self harm",
    "infertile",
    "infertility",
    "ivf",
    "terminally ill",
    "terminal illness",
    "hospitalized",
    "hospitalised",
    "sick leave",
    "medical leave",
    "medical condition",
    "medical record",
    "medical records",
    "medical history",
    "parkinson's",
    "parkinsons",
    "multiple sclerosis",
    "leukemia",
    "leukaemia",
    "suffered a stroke",
    "had a stroke",
    "seizure",
    "seizures",
)
_LEXICON = re.compile(r"\b" + trie_pattern(_TERMS) + r"\b", re.IGNORECASE)
_ACRONYMS = re.compile(r"\b(?:AIDS|STDs?|STIs?|OCD)\b")
_PERSONAL = re.compile(r"\b(?:he|she|him|her|his|hers|himself|herself|my|me|mine|myself|patient)\b", re.IGNORECASE)
_FIRST_PERSON_I = re.compile(r"(?<![\w.'’-])I(?![\w.'’-])")
_I_NOT_PRONOUN = words(
    """
    stage phase type grade class level part chapter war schedule tier category act book volume appendix section
    article title world annex figure table henry louis george elizabeth charles james william edward richard mary
    napoleon pope
    """
)
_NAME = re.compile(r"\b([A-Z][a-z]+(?:[-'’][A-Z]?[a-z]+)?)\s+([A-Z][a-z]+(?:[-'’][A-Z]?[a-z]+)?)\b")
_NOT_PERSON_WORDS = words(
    """
    the a an this that these those in on at for of and but or if when while after before since during our their its
    st saint san santa new los las north south east west hospital clinic center centre university foundation
    institute ministry department health medical cancer society association council trust group inc ltd research
    care services service national royal general memorial children school college board agency office company
    corporation press news times post daily january february march april may june july august september october
    november december monday tuesday wednesday thursday friday saturday sunday mental world day week month awareness
    """
)
_BOUNDARY = re.compile(r"[.!?]+(?=\s|$)|\n")


def _has_personal_reference(sentence: str) -> bool:
    if _PERSONAL.search(sentence):
        return True
    for m in _FIRST_PERSON_I.finditer(sentence):
        prev = re.findall(r"[\w']+", sentence[: m.start()])
        if not prev or prev[-1].lower() not in _I_NOT_PRONOUN:
            return True
    for m in _NAME.finditer(sentence):
        first, last = m.group(1).lower(), m.group(2).lower()
        if first not in _NOT_PERSON_WORDS and last not in _NOT_PERSON_WORDS:
            return True
    return False


_WINDOW = 600  # a "sentence" never extends further than this from the medical term (keeps detection linear)


def _sentence_bounds(text: str, pos: int) -> tuple[int, int]:
    start = max(0, pos - _WINDOW)
    for m in _BOUNDARY.finditer(text, start, pos):
        start = m.end()
    limit = min(len(text), pos + _WINDOW)
    end_match = _BOUNDARY.search(text, pos, limit)
    end = limit if end_match is None else (end_match.end() if end_match.group() != "\n" else end_match.start())
    while start < end and text[start].isspace():
        start += 1
    while end > start and text[end - 1].isspace():
        end -= 1
    return start, end


def medical_sentences(text: str) -> list[tuple[int, int]]:
    """Return ``(start, end)`` spans of sentences that mention a person's health."""
    seen: dict[tuple[int, int], bool] = {}
    hits = [m.start() for m in _LEXICON.finditer(text)] + [m.start() for m in _ACRONYMS.finditer(text)]
    for pos in sorted(hits):
        bounds = _sentence_bounds(text, pos)
        if bounds not in seen:
            seen[bounds] = _has_personal_reference(text[bounds[0] : bounds[1]])
    return [b for b, flagged in seen.items() if flagged]


def detect(scan: Scan) -> Iterator[Detection]:
    """Flag medical content; in restricted mode also redact each such sentence."""
    sentences = medical_sentences(scan.text)
    if not sentences:
        return
    scan.flags.add(SensitivityFlag.MEDICAL)
    if scan.restricted:
        for start, end in sentences:
            yield detection(start, end, RedactionKind.MEDICAL, P_MEDICAL)
