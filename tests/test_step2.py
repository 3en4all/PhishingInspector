from __future__ import annotations

import sys
import unittest
from email import policy
from email.parser import Parser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from phishing_inspector.analyzer import analyze_eml
from phishing_inspector.auth_analysis import parse_authentication_results
from phishing_inspector.domain_analysis import analyze_domain, similarity_ratio
from phishing_inspector.received_analysis import analyze_received_chain
from phishing_inspector.spoofing import analyze_spoofing


class DomainAnalysisTests(unittest.TestCase):
    def test_micros0ft_is_similar_to_microsoft(self) -> None:
        finding = analyze_domain("micros0ft.com")
        self.assertTrue(finding.suspicious)
        self.assertEqual(finding.closest_brand, "microsoft.com")
        self.assertGreaterEqual(finding.similarity or 0.0, 0.82)

    def test_similarity_is_high_for_substitution(self) -> None:
        similarity = similarity_ratio("micros0ft.com", "microsoft.com")
        self.assertGreaterEqual(similarity, 0.90)


class AuthenticationTests(unittest.TestCase):
    def test_authentication_results_are_parsed(self) -> None:
        message = Parser(policy=policy.default).parsestr(
            "Authentication-Results: mx.example; "
            "spf=fail; dkim=pass; dmarc=fail\n\nBody"
        )
        result = parse_authentication_results(message)
        self.assertEqual(result.spf, "fail")
        self.assertEqual(result.dkim, "pass")
        self.assertEqual(result.dmarc, "fail")


class ReceivedTests(unittest.TestCase):
    def test_originating_ip_is_taken_from_oldest_received_header(self) -> None:
        message = Parser(policy=policy.default).parsestr(
            "Received: from second.example (198.51.100.2) by final.example\n"
            "Received: from first.example (203.0.113.50) by second.example\n"
            "\nBody"
        )
        result = analyze_received_chain(message)
        self.assertEqual(result.originating_ip, "203.0.113.50")
        self.assertEqual(len(result.hops), 2)


class SpoofingTests(unittest.TestCase):
    def test_reply_to_mismatch_is_detected(self) -> None:
        message = Parser(policy=policy.default).parsestr(
            "From: Microsoft <support@microsoft.com>\n"
            "Reply-To: attacker@micros0ft.com\n"
            "Return-Path: <bounce@micros0ft.com>\n"
            "\nBody"
        )
        result = analyze_spoofing(message)
        self.assertTrue(result.suspicious)
        self.assertTrue(any("Reply-To" in reason for reason in result.reasons))
        self.assertTrue(
            any("visually similar" in reason.lower() for reason in result.reasons)
        )


class IntegrationTests(unittest.TestCase):
    def test_existing_sample_exposes_step2_data(self) -> None:
        result = analyze_eml(ROOT / "samples" / "suspicious.eml")
        self.assertEqual(result.verdict, "DANGEROUS")
        self.assertEqual(result.authentication["spf"], "fail")
        self.assertEqual(result.authentication["dkim"], "fail")
        self.assertEqual(result.authentication["dmarc"], "fail")
        self.assertEqual(result.received_chain["originating_ip"], "203.0.113.50")
        self.assertTrue(result.spoofing["suspicious"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
