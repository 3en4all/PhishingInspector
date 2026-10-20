from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock

from phishing_inspector import feedback_store
from phishing_inspector.analyzer import analyze_message
from phishing_inspector.html_report import render_html_report
from phishing_inspector.report_model import build_report_model

ROOT = Path(__file__).resolve().parents[1]


class ReportLanguageTests(unittest.TestCase):
    def test_report_has_score_breakdown_and_language(self) -> None:
        analysis = analyze_message(ROOT / "samples" / "suspicious.eml")
        pl = build_report_model(analysis, "pl")
        en = build_report_model(analysis, "en")

        titles = [section.title for section in pl.sections]
        self.assertIn("Score Breakdown", titles)
        breakdown = next(s for s in pl.sections if s.title == "Score Breakdown")
        self.assertEqual([i["code"] for i in breakdown.items], analysis.rule_codes)
        self.assertIn("Score Breakdown", render_html_report(en))

        pl_meaning = next(s for s in pl.sections if s.title == "Risk Findings").items
        en_meaning = next(s for s in en.sections if s.title == "Risk Findings").items
        if pl_meaning:
            self.assertNotEqual(pl_meaning[0]["meaning"], en_meaning[0]["meaning"])


class FeedbackPayloadTests(unittest.TestCase):
    def test_only_rule_codes_are_sent(self) -> None:
        with mock.patch.object(feedback_store, "_rpc", return_value=True) as rpc:
            feedback_store.submit_scan_feedback_cloud(
                verdict="DANGEROUS",
                score=90,
                feedback="correct",
                app_version="test",
                authentication={"spf": "fail", "raw_headers": ["secret header"]},
                finding_codes=["URL_TEXT_MISMATCH", "URL_TEXT_MISMATCH", "jan@example.com"],
                url_rule_codes=["https://evil.example/login"],
                attachment_rule_codes=["ATTACHMENT_HTML"],
            )

        payload = rpc.call_args[0][1]
        self.assertEqual(payload["p_finding_codes"], ["URL_TEXT_MISMATCH"])
        self.assertEqual(payload["p_url_rule_codes"], [])
        self.assertEqual(payload["p_attachment_rule_codes"], ["ATTACHMENT_HTML"])
        self.assertNotIn("secret header", repr(payload))


if __name__ == "__main__":
    unittest.main(verbosity=2)
