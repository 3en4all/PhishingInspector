from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from phishing_inspector.finding_explanations import explain_finding


class ExplanationTests(unittest.TestCase):
    def test_sender_identity(self) -> None:
        text = explain_finding("+15 Sender identity alignment mismatch detected")
        self.assertIn("Adres nadawcy", text)

    def test_spf(self) -> None:
        text = explain_finding("+20 SPF result: fail")
        self.assertIn("SPF", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
