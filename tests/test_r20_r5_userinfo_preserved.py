from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from phishing_inspector.url_analysis import analyze_url


class UserInfoPreservationTests(unittest.TestCase):
    def test_userinfo_at_is_detected_before_normalization(self):
        result = analyze_url("https://user@evil.invalid/path")
        self.assertTrue(result.suspicious)
        self.assertTrue(
            any("user-info" in r.lower() or "using @" in r.lower()
                for r in result.reasons)
        )

    def test_userinfo_password_variant_is_detected(self):
        result = analyze_url("https://user:pass@evil.invalid/path")
        self.assertTrue(result.suspicious)
        self.assertTrue(
            any("user-info" in r.lower() or "using @" in r.lower()
                for r in result.reasons)
        )

    def test_normal_url_without_userinfo_not_affected(self):
        result = analyze_url("https://www.example.org/path")
        self.assertFalse(
            any("user-info" in r.lower() or "using @" in r.lower()
                for r in result.reasons)
        )

    def test_r20_deep_subdomain_still_non_scoring(self):
        result = analyze_url(
            "https://dc5smydh.r.us-east-2.awstrack.me/L0/https://example.com/"
        )
        self.assertFalse(result.suspicious)
        self.assertFalse(
            any("deep subdomain" in r.lower() for r in result.reasons)
        )

    def test_ip_rule_still_works(self):
        result = analyze_url("https://203.0.113.42/path")
        self.assertTrue(result.suspicious)

    def test_shortener_rule_still_works(self):
        result = analyze_url("https://bit.ly/abc123")
        self.assertTrue(result.suspicious)


if __name__ == "__main__":
    unittest.main(verbosity=2)
