from __future__ import annotations

import os
import sys
import unittest
from email import policy
from email.parser import Parser
from pathlib import Path

ROOT = Path(r"C:\PhishingInspector")
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication
from phishing_inspector.auth_analysis import parse_authentication_results
from phishing_inspector.gui_app import MainWindow
from phishing_inspector.models import HeaderAnalysis
from phishing_inspector.scoring import score_analysis
from phishing_inspector.spoofing import analyze_spoofing


def build_message(from_value, return_path, reply_to=None, auth=None):
    lines = [f"From: {from_value}", f"Return-Path: <{return_path}>"]
    if reply_to:
        lines.append(f"Reply-To: {reply_to}")
    if auth:
        lines.append(f"Authentication-Results: mx.example; {auth}")
    lines += ["", "Body"]
    return Parser(policy=policy.default).parsestr("\n".join(lines))


def empty_headers():
    return HeaderAnalysis(
        from_header=None,
        reply_to=None,
        return_path=None,
        subject=None,
        message_id=None,
        authentication_results=[],
        received_headers=[],
        warnings=[],
    )


class SenderIdentityR7R3Tests(unittest.TestCase):
    def assert_no_identity_mismatch(self, message):
        result = analyze_spoofing(message)
        self.assertFalse(
            any("not organizationally aligned" in r.lower() for r in result.reasons),
            result.reasons,
        )

    def test_google(self):
        self.assert_no_identity_mismatch(build_message(
            "Google <noreply-accounts@google.com>",
            "x@scoutcamp.bounces.google.com",
            auth="spf=pass; dkim=pass header.d=google.com; dmarc=pass header.from=google.com",
        ))

    def test_slack(self):
        self.assert_no_identity_mismatch(build_message(
            "Slack <no-reply@slack.com>",
            "x@mail.slack.com",
            reply_to="no-reply@slack.com",
            auth="spf=pass; dkim=pass header.d=slack.com; dmarc=pass header.from=slack.com",
        ))

    def test_supabase(self):
        self.assert_no_identity_mismatch(build_message(
            "Supabase <noreply@supabase.com>",
            "x@pm-bounces.supabase.com",
            auth="spf=pass; dkim=pass header.d=supabase.com; dmarc=pass header.from=supabase.com",
        ))

    def test_fake_microsoft_still_detected(self):
        msg = build_message(
            "Microsoft <support@microsoft.com>",
            "bounce@micros0ft-login.example",
            reply_to="security@micros0ft-login.example",
            auth="spf=fail; dkim=fail header.d=microsoft.com; dmarc=fail header.from=microsoft.com",
        )
        result = analyze_spoofing(msg)
        self.assertTrue(
            any("not organizationally aligned" in r.lower() for r in result.reasons)
        )

    def test_authenticated_external_sender_is_low_signal(self):
        msg = build_message(
            "Example <notice@example.com>",
            "bounce@transaction-mailer.net",
            auth="spf=pass; dkim=pass header.d=example.com; dmarc=pass header.from=example.com",
        )
        spoofing = analyze_spoofing(msg)
        auth = parse_authentication_results(msg)
        score, verdict, reasons = score_analysis(
            headers=empty_headers(),
            urls=[],
            attachments=[],
            authentication=auth,
            spoofing=spoofing,
            received_chain=None,
        )
        self.assertEqual(score, 0)
        self.assertEqual(verdict, "SAFE")
        self.assertTrue(any("context only" in r.lower() for r in reasons))

    def test_branding(self):
        app = QApplication.instance() or QApplication([])
        window = MainWindow()
        self.assertTrue(hasattr(window, "branding_label"))
        self.assertIn("Powered by TechM8", window.branding_label.text())
        window.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
