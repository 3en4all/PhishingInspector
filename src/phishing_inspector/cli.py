from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analyzer import analyze_message
from .html_report import write_html_report
from .pdf_report import write_pdf_report
from .report_model import build_report_model


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishing-inspector",
        description="Analyze EML or MSG files for phishing indicators.",
    )

    parser.add_argument("email", type=Path, help="Path to the EML or MSG file.")
    parser.add_argument("--json", action="store_true", help="Output full analysis as JSON.")
    parser.add_argument(
        "--report-html",
        type=Path,
        help="Write an HTML report to the selected path.",
    )
    parser.add_argument(
        "--report-pdf",
        type=Path,
        help="Write a PDF report to the selected path.",
    )

    parser.add_argument(
        "--network-checks",
        action="store_true",
        help="Also query public DNS for the sender domain's SPF/DMARC records "
        "(sends the domain name to your DNS resolver).",
    )
    parser.add_argument(
        "--language",
        choices=("pl", "en"),
        default="en",
        help="Language of finding explanations in reports.",
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        result = analyze_message(args.email, network_checks=args.network_checks)
    except Exception as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    report = None

    if args.report_html or args.report_pdf:
        report = build_report_model(result, args.language)

    if args.report_html and report is not None:
        output = write_html_report(report, args.report_html)
        print(f"HTML_REPORT = {output}")

    if args.report_pdf and report is not None:
        output = write_pdf_report(report, args.report_pdf)
        print(f"PDF_REPORT = {output}")

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
        return 0

    print("Phishing Inspector")
    print("==================")
    print(f"File:    {result.source_file}")
    print(f"Verdict: {result.verdict}")
    print(f"Score:   {result.score}/100")
    print()

    print("Reasons:")
    for reason in result.reasons:
        print(f"- {reason}")

    if result.findings:
        print()
        print("Score breakdown:")
        for finding in result.findings:
            print(f"- {finding.code} (+{finding.points}): {finding.message}")

    if result.limitations:
        print()
        print("Limitations:")
        for item in result.limitations:
            print(f"- {item}")

    print()
    print(f"URLs: {len(result.urls)}")
    print(f"Attachments: {len(result.attachments)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
