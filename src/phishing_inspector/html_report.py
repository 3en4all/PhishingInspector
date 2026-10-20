from __future__ import annotations

import html
from pathlib import Path

from .report_model import ReportModel


def render_html_report(report: ReportModel) -> str:
    sections_html: list[str] = []

    for section in report.sections:
        items_html: list[str] = []

        for item in section.items:
            rows = "".join(
                "<tr>"
                f"<th>{html.escape(str(key))}</th>"
                f"<td>{html.escape(str(value))}</td>"
                "</tr>"
                for key, value in item.items()
            )
            items_html.append(f'<table class="item">{rows}</table>')

        sections_html.append(
            f"<section><h2>{html.escape(section.title)}</h2>"
            + "".join(items_html)
            + "</section>"
        )

    css = """
body { font-family: Arial, sans-serif; margin: 32px; line-height: 1.5; }
h1, h2 { margin-bottom: 12px; }
.summary { padding: 16px; border: 1px solid #bbb; margin-bottom: 20px; }
.item { border-collapse: collapse; width: 100%; margin-bottom: 12px; }
.item th, .item td { border: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; }
.item th { width: 220px; }
"""

    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        f"<title>{html.escape(report.title)}</title>"
        f"<style>{css}</style></head><body>"
        f"<h1>{html.escape(report.title)}</h1>"
        "<div class=\"summary\">"
        f"<strong>Source:</strong> {html.escape(report.source_file)}<br>"
        f"<strong>Verdict:</strong> {html.escape(report.verdict)}<br>"
        f"<strong>Score:</strong> {report.score}/100<br>"
        f"<p>{html.escape(report.summary)}</p>"
        "</div>"
        + "".join(sections_html)
        + "</body></html>"
    )


def write_html_report(report: ReportModel, path: str | Path) -> Path:
    output = Path(path).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_html_report(report), encoding="utf-8")
    return output
