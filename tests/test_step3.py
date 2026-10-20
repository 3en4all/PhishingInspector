from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from phishing_inspector.alignment import build_alignment, relaxed_align
from phishing_inspector.analyzer import analyze_eml
from phishing_inspector.url_analysis import normalize_url, analyze_url


class AlignmentTests(unittest.TestCase):
    def test_relaxed_alignment_accepts_subdomains(self) -> None:
        self.assertTrue(relaxed_align("mail.example.com", "example.com"))

    def test_alignment_detects_mismatch(self) -> None:
        result = build_alignment(
            from_domain="microsoft.com",
            return_path_domain="micros0ft-login.example",
            dkim_domain="microsoft.com",
        )

        self.assertFalse(result.spf_aligned)
        self.assertTrue(result.dkim_aligned)


class UrlNormalizationTests(unittest.TestCase):
    def test_default_https_port_is_removed(self) -> None:
        normalized = normalize_url("HTTPS://Example.COM:443/login")
        self.assertEqual(normalized, "https://example.com/login")

    def test_brand_in_subdomain_is_detected(self) -> None:
        result = analyze_url("https://microsoft.com.secure-login.example/auth")
        self.assertTrue(result.suspicious)
        self.assertTrue(
            any("brand-like term" in reason.lower() for reason in result.reasons)
        )


class Step3IntegrationTests(unittest.TestCase):
    def test_sample_contains_alignment_and_dns_sections(self) -> None:
        result = analyze_eml(ROOT / "samples" / "suspicious.eml")

        self.assertIn("alignment", result.authentication)
        self.assertIn("dns_checks", result.authentication)
        self.assertFalse(result.authentication["alignment"]["spf_aligned"])
        self.assertTrue(result.authentication["alignment"]["dkim_aligned"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
