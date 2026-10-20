from __future__ import annotations

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from .report_model import ReportModel


def _safe(value: object) -> str:
    if value is None:
        return "-"
    return str(value)


def write_pdf_report(report: ReportModel, path: str | Path) -> Path:
    output = Path(path).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        str(output),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=report.title,
        author="Phishing Inspector",
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "TitleCenter",
        parent=styles["Title"],
        alignment=TA_CENTER,
        spaceAfter=12,
    )

    verdict_style = ParagraphStyle(
        "Verdict",
        parent=styles["Heading2"],
        alignment=TA_CENTER,
        spaceAfter=10,
    )

    story = [
        Paragraph(report.title, title_style),
        Paragraph(f"Verdict: {report.verdict}", verdict_style),
        Paragraph(f"Risk score: {report.score}/100", styles["Heading3"]),
        Spacer(1, 6),
        Paragraph(f"Source file: {_safe(report.source_file)}", styles["BodyText"]),
        Spacer(1, 8),
        Paragraph(report.summary, styles["BodyText"]),
        Spacer(1, 14),
    ]

    for section_index, section in enumerate(report.sections):
        if section_index > 0:
            story.append(Spacer(1, 8))

        story.append(Paragraph(section.title, styles["Heading2"]))

        if not section.items:
            story.append(Paragraph("No data.", styles["BodyText"]))
            continue

        for item in section.items:
            rows = []

            for key, value in item.items():
                rows.append(
                    [
                        Paragraph(f"<b>{_safe(key)}</b>", styles["BodyText"]),
                        Paragraph(_safe(value), styles["BodyText"]),
                    ]
                )

            table = Table(
                rows,
                colWidths=[48 * mm, 112 * mm],
                repeatRows=0,
                hAlign="LEFT",
            )

            table.setStyle(
                TableStyle(
                    [
                        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("BACKGROUND", (0, 0), (0, -1), colors.whitesmoke),
                        ("LEFTPADDING", (0, 0), (-1, -1), 6),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                        ("TOPPADDING", (0, 0), (-1, -1), 5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ]
                )
            )

            story.append(table)
            story.append(Spacer(1, 8))

    doc.build(story)
    return output
