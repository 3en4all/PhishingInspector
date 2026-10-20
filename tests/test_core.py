from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from phishing_inspector.analyzer import analyze_eml
from phishing_inspector.attachment_analysis import analyze_attachment
from phishing_inspector.url_analysis import analyze_url


class UrlAnalysisTests(unittest.TestCase):
    def test_ip_based_login_url_is_suspicious(self) -> None:
        result = analyze_url("https://203.0.113.50/login/verify")
        self.assertTrue(result.suspicious)
        self.assertTrue(any("IP address" in reason for reason in result.reasons))


class AttachmentAnalysisTests(unittest.TestCase):
    def test_double_extension_executable_is_suspicious(self) -> None:
        result = analyze_attachment(
            filename="Invoice.pdf.exe",
            content_type="application/octet-stream",
            payload=b"MZ-test",
        )

        self.assertTrue(result.suspicious)
        self.assertEqual(len(result.sha256), 64)
        self.assertTrue(any("High-risk" in reason for reason in result.reasons))


class EmailAnalysisTests(unittest.TestCase):
    def test_suspicious_sample_is_dangerous(self) -> None:
        sample = ROOT / "samples" / "suspicious.eml"
        result = analyze_eml(sample)

        self.assertEqual(result.verdict, "DANGEROUS")
        self.assertGreaterEqual(result.score, 50)
        self.assertEqual(len(result.urls), 1)
        self.assertEqual(len(result.attachments), 1)
        self.assertTrue(any("Reply-To" in warning for warning in result.headers.warnings))
        self.assertTrue(any("Return-Path" in warning for warning in result.headers.warnings))


if __name__ == "__main__":
    unittest.main(verbosity=2)
