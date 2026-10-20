from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from phishing_inspector.url_analysis import analyze_url


class TrustedUrlTests(unittest.TestCase):
    def test_google_account_url_is_not_suspicious_by_term_only(self) -> None:
        result = analyze_url("https://accounts.google.com/account/permissions")
        self.assertFalse(result.suspicious)

    def test_fake_google_subdomain_is_suspicious(self) -> None:
        result = analyze_url("https://google.com.secure-login.example/account")
        self.assertTrue(result.suspicious)


if __name__ == "__main__":
    unittest.main(verbosity=2)
