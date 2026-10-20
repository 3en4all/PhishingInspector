from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from phishing_inspector.url_analysis import analyze_url


class ContextualLureSignalTests(unittest.TestCase):
    def test_normal_account_path_is_not_suspicious_by_itself(self) -> None:
        result = analyze_url("https://example.org/account/settings")
        self.assertFalse(result.suspicious)
        self.assertFalse(
            any("lure related term" in reason.lower() for reason in result.reasons)
        )

    def test_normal_invoice_path_is_not_suspicious_by_itself(self) -> None:
        result = analyze_url("https://billing.example.org/invoice/12345")
        self.assertFalse(result.suspicious)

    def test_normal_login_path_is_not_suspicious_by_itself(self) -> None:
        result = analyze_url("https://portal.example.org/login")
        self.assertFalse(result.suspicious)

    def test_ip_login_keeps_strong_and_lure_signals(self) -> None:
        result = analyze_url("https://203.0.113.50/login/verify")
        self.assertTrue(result.suspicious)
        self.assertTrue(any("IP address" in reason for reason in result.reasons))
        self.assertTrue(
            any("lure related term" in reason.lower() for reason in result.reasons)
        )

    def test_shortener_login_remains_suspicious(self) -> None:
        result = analyze_url("https://bit.ly/login")
        self.assertTrue(result.suspicious)
        self.assertTrue(
            any("shortening" in reason.lower() for reason in result.reasons)
        )

    def test_fake_brand_deep_subdomain_remains_suspicious(self) -> None:
        result = analyze_url(
            "https://google.com.secure-login.example/account/verify"
        )
        self.assertTrue(result.suspicious)


if __name__ == "__main__":
    unittest.main(verbosity=2)
