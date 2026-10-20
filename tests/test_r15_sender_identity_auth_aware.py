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
        from_header="Brand <hello@brand.example>",
        reply_to=None,
        return_path="<bounce@mailer.example>",
        subject="Test",
        message_id="<test@example>",
        authentication_results=[],
        received_headers=["from mailer.example"],
        warnings=[],
    )


def spoofing(reasons: list[str]):
    return SimpleNamespace(
        suspicious=bool(reasons),
        reasons=reasons,
        from_domain="brand.example",
        reply_to_domain=None,
        return_path_domain="mailer.example",
    )


def auth(spf: str, dkim: str, dmarc: str):
    return SimpleNamespace(
        spf=spf,
        dkim=dkim,
        dmarc=dmarc,
        dkim_domain=None,
        warnings=[],
        raw_headers=[],
    )


MISMATCH = (
    "From domain is not organizationally aligned with Return-Path domain: "
    "brand.example != mailer.example"
)


class SenderIdentityAuthAwareTests(unittest.TestCase):
    def call_score(self, authentication, spoofing_obj):
        return score_analysis(
            headers=headers(),
            urls=[],
            attachments=[],
            authentication=authentication,
            spoofing=spoofing_obj,
            received_chain=None,
        )

    def test_dmarc_pass_makes_sender_mismatch_context_only(self) -> None:
        score, verdict, reasons = self.call_score(
            auth("unknown", "unknown", "pass"),
            spoofing([MISMATCH]),
        )
        self.assertEqual(score, 0)
        self.assertEqual(verdict, "SAFE")
        self.assertTrue(any("context only" in r.lower() for r in reasons))

    def test_two_auth_passes_make_sender_mismatch_context_only(self) -> None:
        score, verdict, reasons = self.call_score(
            auth("pass", "pass", "unknown"),
            spoofing([MISMATCH]),
        )
        self.assertEqual(score, 0)
        self.assertEqual(verdict, "SAFE")
        self.assertTrue(any("context only" in r.lower() for r in reasons))

    def test_one_auth_pass_keeps_reduced_sender_signal(self) -> None:
        score, verdict, reasons = self.call_score(
            auth("pass", "unknown", "unknown"),
            spoofing([MISMATCH]),
        )
        self.assertEqual(score, 10)
        self.assertEqual(verdict, "SAFE")
        self.assertTrue(any("+10 Sender identity" in r for r in reasons))

    def test_no_auth_keeps_full_sender_signal(self) -> None:
        score, verdict, reasons = self.call_score(
            auth("unknown", "unknown", "unknown"),
            spoofing([MISMATCH, MISMATCH]),
        )
        self.assertEqual(score, 30)
        self.assertEqual(verdict, "SUSPICIOUS")
        self.assertTrue(any("+30 Sender identity" in r for r in reasons))

    def test_auth_fail_plus_mismatch_remains_dangerous(self) -> None:
        score, verdict, _ = self.call_score(
            auth("fail", "fail", "fail"),
            spoofing([MISMATCH]),
        )
        self.assertGreaterEqual(score, 50)
        self.assertEqual(verdict, "DANGEROUS")

    def test_lookalike_stays_strong_even_with_auth_pass(self) -> None:
        lookalike = (
            "Return-Path domain: Domain is visually similar to protected "
            "brand domain: microsoft.com (95%)"
        )
        score, verdict, reasons = self.call_score(
            auth("pass", "pass", "pass"),
            spoofing([MISMATCH, lookalike]),
        )
        self.assertGreaterEqual(score, 25)
        self.assertEqual(verdict, "SUSPICIOUS")
        self.assertTrue(any("Lookalike" in r for r in reasons))


if __name__ == "__main__":
    unittest.main(verbosity=2)
