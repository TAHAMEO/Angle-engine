"""Render a :class:`ReportDocument` as HTML, Markdown, JSON or PDF.

HTML comes from an autoescaping Jinja2 template with inline print CSS and no scripts or external resources.
PDF is produced by WeasyPrint from that HTML with every URL fetch refused, so rendering never touches the network
or the file system. Markdown escapes all user-originated text.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from angel_engine.reports.document import ReportDocument

TEMPLATES = Path(__file__).resolve().parent / "templates"
STATUS_MARKS = {
    "confirmed_by_source": "✓",
    "corroborated": "✓✓",
    "unverified": "?",
    "contradicted": "✗",
    "ai_hypothesis": "◇",
}
MEDIA_TYPES = {
    "html": "text/html; charset=utf-8",
    "markdown": "text/markdown; charset=utf-8",
    "json": "application/json",
    "pdf": "application/pdf",
}
EXTENSIONS = {"html": "html", "markdown": "md", "json": "json", "pdf": "pdf"}
_CSS_SAFE = re.compile(r"[^A-Za-z0-9 .:#/()\-·—]")
_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]<>|#])")


@lru_cache(maxsize=1)
def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES)),
        autoescape=select_autoescape(enabled_extensions=("html", "j2"), default=True),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _css_text(value: str) -> str:
    return _CSS_SAFE.sub("", value)[:160]


def footer_text(doc: ReportDocument) -> str:
    integrity = doc.integrity
    if integrity.get("sha256"):
        return f"Report {doc.report_id} · SHA-256 {integrity['sha256'][:16]} · Audit #{integrity.get('audit_seq')}"
    return f"Draft report {doc.report_id}"


def render_html(doc: ReportDocument) -> str:
    watermark = "DRAFT" if doc.status != "final" else doc.confidentiality.upper()
    return (
        _env()
        .get_template("report.html.j2")
        .render(
            doc=doc,
            status_label="Final" if doc.status == "final" else "Draft",
            status_marks=STATUS_MARKS,
            watermark=watermark,
            css_footer=_css_text(footer_text(doc)),
            css_confidentiality=_css_text(f"{doc.confidentiality} · {doc.investigation_ref}"),
        )
    )


def _md(text: Any) -> str:
    return _MD_SPECIAL.sub(r"\\\1", " ".join(str(text or "").split()))


def _md_refs(refs: list[Any]) -> str:
    return f" [{', '.join(r.label for r in refs)}]" if refs else ""


def render_markdown(doc: ReportDocument) -> str:
    out = [
        f"# {_md(doc.title)}",
        "",
        f"*Angel Engine investigation report · {_md(doc.confidentiality)} · {_md(doc.investigation_ref)} · "
        f"{'Final' if doc.status == 'final' else 'Draft'} · generated {_md(doc.generated_at)} UTC*",
        "",
    ]
    if doc.restricted_mode:
        out += ["> **Restricted mode** — this investigation concerns an individual. Handle with particular care.", ""]
    for section in doc.sections:
        out += [f"## {_md(section.title)}", ""]
        for block in section.blocks:
            out += _md_block(block)
    if doc.integrity.get("sha256"):
        out += [
            "---",
            "",
            f"Final report `{doc.report_id}`. SHA-256 `{doc.integrity['sha256']}`. Integrity code "
            f"`{doc.integrity.get('mac_prefix')}`. Audit log entry #{doc.integrity.get('audit_seq')} "
            f"({_md(doc.integrity.get('finalized_at'))} UTC).",
            "",
        ]
    else:
        out += ["---", "", f"Draft report `{doc.report_id}` — not finalized; content may change.", ""]
    out.append(
        "Verification statuses are human decisions; AI output is labelled as AI hypothesis. Angel Engine does "
        "not perform facial identification."
    )
    return "\n".join(out) + "\n"


def _md_table(columns: list[str], rows: list[list[Any]]) -> list[str]:
    lines = ["| " + " | ".join(_md(c) for c in columns) + " |", "|" + "---|" * len(columns)]
    lines += ["| " + " | ".join(_md(v) for v in row) + " |" for row in rows]
    return [*lines, ""]


def _md_block(block: Any) -> list[str]:
    data = block.data
    if block.type == "paragraph":
        note = f" *[{_md(data['note'])}]*" if data.get("note") else ""
        return [f"{_md(block.text)}{_md_refs(block.refs)}{note}", ""]
    if block.type == "notice":
        return [f"> {_md(block.text)}", ""]
    if block.type == "ai_segment":
        label = f" *[{_md(data['label'])}]*" if data.get("label") else ""
        return [f"> *AI:* {_md(block.text)}{_md_refs(block.refs)}{label}", ""]
    if block.type == "list":
        return [*(f"- {_md(item)}" for item in data.get("items", [])), ""]
    if block.type == "facts":
        return _md_table(["Field", "Value"], data.get("rows", []))
    if block.type == "table":
        caption = [f"**{_md(block.text)}**", ""] if block.text else []
        return caption + _md_table(data.get("columns", []), data.get("rows", []))
    if block.type == "finding":
        mark = STATUS_MARKS.get(data.get("status", ""), "")
        lines = [
            f"### {_md(data['label'])} · {mark} {_md(data['status_label'])} · {_md(data['provenance_label'])}",
            "",
            f"**{_md(block.text)}**{_md_refs(block.refs)}",
            "",
        ]
        if data.get("confidence"):
            basis = data["confidence"].get("basis")
            lines += [f"Confidence: {_md(data['confidence']['level'])}" + (f" — {_md(basis)}" if basis else ""), ""]
        if data.get("note"):
            lines += [f"> {_md(data['note'])}", ""]
        if data.get("evidence"):
            rows = [
                [
                    e["label"],
                    e["stance"],
                    e["origin"],
                    e.get("source") or "—",
                    e.get("captured") or "—",
                    e.get("published") or "—",
                    e["provenance"],
                ]
                for e in data["evidence"]
            ]
            lines += _md_table(["Evidence", "Stance", "Origin", "Source", "Captured", "Published", "Provenance"], rows)
        return lines
    return []


def render_json(doc: ReportDocument) -> str:
    return json.dumps(
        {"format": "angel-engine-report", "version": 1, "document": doc.as_dict()},
        indent=2,
        ensure_ascii=False,
        default=str,
    )


def _refuse_fetch(url: str, *args: Any, **kwargs: Any) -> dict[str, Any]:
    raise ValueError("report rendering never fetches resources")


def render_pdf(doc: ReportDocument) -> bytes:
    from weasyprint import HTML

    return bytes(HTML(string=render_html(doc), url_fetcher=_refuse_fetch).write_pdf())


def render(doc: ReportDocument, fmt: str) -> bytes:
    if fmt == "html":
        return render_html(doc).encode()
    if fmt == "markdown":
        return render_markdown(doc).encode()
    if fmt == "json":
        return render_json(doc).encode()
    if fmt == "pdf":
        return render_pdf(doc)
    raise ValueError(f"unknown format {fmt!r}")


__all__ = ["EXTENSIONS", "MEDIA_TYPES", "footer_text", "render", "render_html", "render_json", "render_markdown"]
