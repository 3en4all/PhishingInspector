from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
TESTS = Path(__file__).resolve().parent

for path in (SRC, TESTS):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from corpus import LEGITIMATE, PHISHING  # noqa: E402
from phishing_inspector.analyzer import analyze_message  # noqa: E402

ORDER = {"SAFE": 0, "SUSPICIOUS": 1, "DANGEROUS": 2}


def analyze_raw(raw: str):
    with tempfile.TemporaryDirectory() as temp_dir:
        path = Path(temp_dir) / "case.eml"
        path.write_text(raw, encoding="utf-8")
        return analyze_message(path)


class PhishingIsCaughtTests(unittest.TestCase):
    def test_phishing_cases(self) -> None:
        for case in PHISHING:
            with self.subTest(case.name):
                result = analyze_raw(case.raw)
                self.assertGreaterEqual(
                    ORDER[result.verdict], ORDER[case.expected],
                    f"{case.name}: {result.verdict} {result.score} {result.reasons}",
                )
                for code in case.must_have:
                    self.assertIn(code, result.rule_codes, f"{case.name}: {result.reasons}")


class LegitimateStaysQuietTests(unittest.TestCase):
    def test_legitimate_cases(self) -> None:
        for case in LEGITIMATE:
            with self.subTest(case.name):
                result = analyze_raw(case.raw)
                self.assertEqual(
                    result.verdict, "SAFE",
                    f"{case.name}: {result.score} {result.reasons}",
                )


class PrivacyTests(unittest.TestCase):
    def test_no_dns_queries_by_default(self) -> None:
        from unittest import mock

        with mock.patch("phishing_inspector.dns_auth._query_txt_records") as query:
            result = analyze_raw(PHISHING[1].raw)

        query.assert_not_called()
        self.assertFalse(result.authentication["dns_checks"]["enabled"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
