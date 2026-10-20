"""Rules added after the second synthetic corpus (0.3.1)."""
from __future__ import annotations

import unittest

from phishing_inspector.brands import brand_in_text, brand_named, brand_owning


class BrandNameTests(unittest.TestCase):
    def test_short_alias_needs_capitals(self) -> None:
        self.assertIsNone(brand_in_text("Ing. Petr Novak"))
        self.assertEqual(brand_in_text("ING Bank Slaski").key, "ing")
        self.assertEqual(brand_in_text("Powiadomienie PKO").key, "pko")
        self.assertIsNone(brand_in_text("Zus i spolka"))

    def test_pko_group_domains_belong_to_pko(self) -> None:
        self.assertEqual(brand_owning("pkoleasing.pl").key, "pko")

    def test_disguised_display_names(self) -> None:
        for name, key in (("PayPaI", "paypal"), ("Allegr0 Pomoc", "allegro"),
                          ("\u0410pple Support", "apple"), ("N3tflix", "netflix")):
            with self.subTest(name):
                self.assertEqual(brand_named(name), (brand_named(name)[0], True))
                self.assertEqual(brand_named(name)[0].key, key)

    def test_plain_names_are_not_brands(self) -> None:
        for name in ("Jan Kowalski", "Biuro 365", "IT Helpdesk", "Ola Isabel", "Sklep 24/7"):
            with self.subTest(name):
                self.assertIsNone(brand_named(name))


if __name__ == "__main__":
    unittest.main()
