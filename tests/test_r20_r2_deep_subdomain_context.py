from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from phishing_inspector.url_analysis import analyze_url


class DeepSubdomainContextR20R2Tests(unittest.TestCase):
    def test_deep_tracking_host_is_not_suspicious_by_itself(self):
        result = analyze_url(
            "https://dc5smydh.r.us-east-2.awstrack.me/L0/https://example.com/"
        )
        self.assertFalse(result.suspicious)
        self.assertFalse(
            any("deep subdomain" in reason.lower() for reason in result.reasons)
        )

    def test_deep_s3_host_is_not_suspicious_by_itself(self):
        result = analyze_url(
            "https://yanosik-bucket.s3.eu-west-1.amazonaws.com/assets/logo.png"
        )
        self.assertFalse(result.suspicious)

    def test_user_info_syntax_still_suspicious(self):
        result = analyze_url("https://user@evil.invalid/path")
        self.assertTrue(result.suspicious)
        self.assertTrue(
            any("user-info" in reason.lower() or "using @" in reason.lower()
                for reason in result.reasons)
        )

    def test_brand_like_subdomain_still_suspicious(self):
        result = analyze_url(
            "https://google.com.secure-login.example/account"
        )
        self.assertTrue(result.suspicious)
        self.assertTrue(
            any("brand-like" in reason.lower() for reason in result.reasons)
        )

    def test_shortener_still_suspicious(self):
        result = analyze_url("https://bit.ly/abc123")
        self.assertTrue(result.suspicious)

    def test_ip_host_still_suspicious(self):
        result = analyze_url("https://203.0.113.42/path")
        self.assertTrue(result.suspicious)


if __name__ == "__main__":
    unittest.main(verbosity=2)
