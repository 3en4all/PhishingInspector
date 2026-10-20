from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from phishing_inspector.analyzer import analyze_message
from phishing_inspector.html_report import render_html_report
from phishing_inspector.message_loader import UnsupportedMessageFormatError
from phishing_inspector.report_model import build_report_model


class MessageLoaderTests(unittest.TestCase):
    def test_eml_still_works_through_generic_loader(self) -> None:
        result = analyze_message(ROOT / "samples" / "suspicious.eml")
        self.assertEqual(result.verdict, "DANGEROUS")

    def test_unsupported_extension_is_rejected(self) -> None:
        from phishing_inspector.message_loader import load_message

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "message.txt"
            path.write_text("hello", encoding="utf-8")

            with self.assertRaises(UnsupportedMessageFormatError):
                load_message(path)


class ReportTests(unittest.TestCase):
    def test_report_model_is_built(self) -> None:
        analysis = analyze_message(ROOT / "samples" / "suspicious.eml")
        report = build_report_model(analysis)

        self.assertEqual(report.verdict, "DANGEROUS")
        self.assertGreaterEqual(len(report.sections), 5)

    def test_html_report_contains_core_fields(self) -> None:
        analysis = analyze_message(ROOT / "samples" / "suspicious.eml")
        report = build_report_model(analysis)
        rendered = render_html_report(report)

        self.assertIn("Phishing Inspector Report", rendered)
        self.assertIn("DANGEROUS", rendered)
        self.assertIn("Risk Findings", rendered)


if __name__ == "__main__":
    unittest.main(verbosity=2)
