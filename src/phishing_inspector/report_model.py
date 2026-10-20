from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .i18n import explain_finding, normalize_language
from .models import EmailAnalysis


@dataclass(slots=True)
class ReportSection:
    title: str
    items: list[dict[str, Any]] = field(default_factory=list)


@dataclass(slots=True)
class ReportModel:
    title: str
    source_file: str
    verdict: str
    score: int
    summary: str
    sections: list[ReportSection]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_report_model(analysis: EmailAnalysis, language: str = "pl") -> ReportModel:
    language = normalize_language(language)
    summary = (
        f"Verdict: {analysis.verdict}. "
        f"Risk score: {analysis.score}/100. "
        f"Detected {len(analysis.urls)} URL(s) and "
        f"{len(analysis.attachments)} attachment(s)."
    )

    sections = [
        ReportSection(
            title="Message Headers",
            items=[
                {"name": "From", "value": analysis.headers.from_header},
                {"name": "Reply-To", "value": analysis.headers.reply_to},
                {"name": "Return-Path", "value": analysis.headers.return_path},
                {"name": "Subject", "value": analysis.headers.subject},
                {"name": "Message-ID", "value": analysis.headers.message_id},
            ],
        ),
        ReportSection(
            title="Authentication",
            items=[
                {"name": "SPF", "value": analysis.authentication.get("spf")},
                {"name": "DKIM", "value": analysis.authentication.get("dkim")},
                {"name": "DMARC", "value": analysis.authentication.get("dmarc")},
                {
                    "name": "SPF aligned",
                    "value": analysis.authentication.get("alignment", {}).get("spf_aligned"),
                },
                {
                    "name": "DKIM aligned",
                    "value": analysis.authentication.get("alignment", {}).get("dkim_aligned"),
                },
            ],
        ),
        ReportSection(
            title="URLs",
            items=[
                {
                    "url": item.url,
                    "hostname": item.hostname,
                    "link_text": getattr(item, "link_text", None),
                    "source": getattr(item, "source", None),
                    "suspicious": item.suspicious,
                    "rule_codes": list(getattr(item, "rule_codes", [])),
                    "reasons": list(item.reasons),
                }
                for item in analysis.urls
            ],
        ),
        ReportSection(
            title="Attachments",
            items=[
                {
                    "filename": item.filename,
                    "content_type": item.content_type,
                    "size": item.size,
                    "sha256": item.sha256,
                    "suspicious": item.suspicious,
                    "rule_codes": list(getattr(item, "rule_codes", [])),
                    "reasons": list(item.reasons),
                }
                for item in analysis.attachments
            ],
        ),
        ReportSection(
            title="Risk Findings",
            items=[
                {"finding": reason, "meaning": explain_finding(reason, language)}
                for reason in analysis.reasons
            ],
        ),
        ReportSection(
            title="Score Breakdown",
            items=[
                {"code": finding.code, "points": finding.points, "message": finding.message}
                for finding in getattr(analysis, "findings", [])
            ],
        ),
    ]

    limitations = list(getattr(analysis, "limitations", []))
    if limitations:
        sections.append(
            ReportSection(
                title="Analysis Limitations",
                items=[{"limitation": item} for item in limitations],
            )
        )

    return ReportModel(
        title="Phishing Inspector Report",
        source_file=analysis.source_file,
        verdict=analysis.verdict,
        score=analysis.score,
        summary=summary,
        sections=sections,
    )
