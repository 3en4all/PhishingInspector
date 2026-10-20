"""Rules added after the second synthetic corpus (0.3.1)."""
from __future__ import annotations

import unittest

from phishing_inspector.brands import brand_in_text, brand_owning


class BrandNameTests(unittest.TestCase):
    def test_short_alias_needs_capitals(self) -> None:
        self.assertIsNone(brand_in_text("Ing. Petr Novak"))
        self.assertEqual(brand_in_text("ING Bank Slaski").key, "ing")
        self.assertEqual(brand_in_text("Powiadomienie PKO").key, "pko")
        self.assertIsNone(brand_in_text("Zus i spolka"))

    def test_pko_group_domains_belong_to_pko(self) -> None:
        self.assertEqual(brand_owning("pkoleasing.pl").key, "pko")


if __name__ == "__main__":
    unittest.main()
