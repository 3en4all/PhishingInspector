from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from phishing_inspector.scoring import score_analysis


def headers():
    return SimpleNamespace(
        warnings=[],
        authentication_results=[],
    )


def auth(spf="unknown", dkim="unknown", dmarc="unknown"):
    return SimpleNamespace(
        spf=spf,
        dkim=dkim,
        dmarc=dmarc,
    )


def spoofing():
    return SimpleNamespace(
        reasons=[],
        suspicious=False,
    )


class DkimDmarcContextTests(unittest.TestCase):
    def call_score(self, authentication):
        return score_analysis(
            headers=headers(),
            urls=[],
            attachments=[],
            authentication=authentication,
            spoofing=spoofing(),
            received_chain=None,
        )

    def test_dkim_fail_dmarc_pass_is_context_only(self):
        score, verdict, reasons = self.call_score(
            auth(spf="pass", dkim="fail", dmarc="pass")
        )
        self.assertEqual(score, 0)
        self.assertEqual(verdict, "SAFE")
        self.assertTrue(
            any("dkim result: fail" in r.lower() and "context only" in r.lower()
                for r in reasons)
        )

    def test_dkim_fail_without_dmarc_pass_still_scores(self):
        score, verdict, reasons = self.call_score(
            auth(spf="pass", dkim="fail", dmarc="unknown")
        )
        self.assertEqual(score, 20)
        self.assertEqual(verdict, "SUSPICIOUS")
        self.assertTrue(any("+20 DKIM result: fail" in r for r in reasons))

    def test_dkim_fail_and_dmarc_fail_remains_strong(self):
        score, verdict, reasons = self.call_score(
            auth(spf="fail", dkim="fail", dmarc="fail")
        )
        self.assertGreaterEqual(score, 50)
        self.assertEqual(verdict, "DANGEROUS")
        self.assertTrue(any("+25 DMARC result: fail" in r for r in reasons))

    def test_dkim_pass_dmarc_pass_unchanged(self):
        score, verdict, _ = self.call_score(
            auth(spf="pass", dkim="pass", dmarc="pass")
        )
        self.assertEqual(score, 0)
        self.assertEqual(verdict, "SAFE")


if __name__ == "__main__":
    unittest.main(verbosity=2)
