from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from phishing_inspector.analyzer import analyze_message
from phishing_inspector.pdf_report import write_pdf_report
from phishing_inspector.report_model import build_report_model


class PdfReportTests(unittest.TestCase):
    def test_pdf_report_is_created(self) -> None:
        analysis = analyze_message(ROOT / "samples" / "suspicious.eml")
        report = build_report_model(analysis)

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "report.pdf"
            result = write_pdf_report(report, output)

            self.assertTrue(result.exists())
            self.assertGreater(result.stat().st_size, 1000)

            header = result.read_bytes()[:5]
            self.assertEqual(header, b"%PDF-")


try:
    import extract_msg  # type: ignore  # noqa: F401
    HAS_EXTRACT_MSG = True
except ImportError:
    HAS_EXTRACT_MSG = False


class MsgDependencyTests(unittest.TestCase):
    @unittest.skipUnless(HAS_EXTRACT_MSG, "optional extra 'msg' (extract-msg) not installed")
    def test_extract_msg_import_is_available(self) -> None:
        import extract_msg  # type: ignore

        self.assertIsNotNone(extract_msg)


class MsgLoaderTests(unittest.TestCase):
    """load_msg() with a stand-in for extract_msg, so it runs everywhere."""

    def _fake_module(self, header):
        import types
        from email.message import Message

        attachment = types.SimpleNamespace(
            longFilename="Faktura.html",
            data=b"<form action='https://evil.example/p'><input type=password></form>",
            mimetype="text/html",
        )

        class FakeMessage:
            def __init__(self, _path):
                self.header = header
                self.sender = "PayPal <service@paypa1-secure.top>"
                self.to = "victim@example.org"
                self.cc = None
                self.subject = "Konto"
                self.body = "Tekst"
                self.htmlBody = b'<a href="https://paypa1-secure.top/login">https://www.paypal.com</a>'
                self.attachments = [attachment]

        module = types.ModuleType("extract_msg")
        module.Message = FakeMessage
        return module

    def _load(self, header):
        from unittest import mock

        from phishing_inspector.analyzer import analyze_message

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "message.msg"
            path.write_bytes(b"not used by the fake")
            with mock.patch.dict(sys.modules, {"extract_msg": self._fake_module(header)}):
                return analyze_message(path)

    def test_transport_headers_html_and_attachments_are_used(self) -> None:
        from email.message import Message

        header = Message()
        header["From"] = "PayPal <service@paypa1-secure.top>"
        header["Return-Path"] = "<bounce@evil.example>"
        header["Authentication-Results"] = "mx.example.org; spf=fail; dmarc=fail"
        header["Received"] = "from evil (203.0.113.9) by mx.example.org"

        result = self._load(header)

        self.assertEqual(result.authentication["spf"], "fail")
        self.assertTrue(any(u.link_text for u in result.urls))
        self.assertIn("ATTACHMENT_HTML_ACTIVE", result.rule_codes)
        self.assertEqual(result.verdict, "DANGEROUS")
        self.assertEqual(result.limitations, [])

    def test_missing_transport_headers_are_reported(self) -> None:
        result = self._load(None)
        self.assertTrue(result.limitations)


if __name__ == "__main__":
    unittest.main(verbosity=2)
