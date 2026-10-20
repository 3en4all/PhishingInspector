"""Rules added after the second synthetic corpus (0.3.1)."""
from __future__ import annotations

import unittest

from phishing_inspector.url_analysis import analyze_url
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


class BrandSubdomainTests(unittest.TestCase):
    def test_short_brand_as_subdomain_label(self) -> None:
        info = analyze_url("https://olx.bezpieczna-transakcja24.pl/odbierz")
        self.assertIn("URL_BRAND_SUBDOMAIN", info.rule_codes)

    def test_short_brand_inside_word_is_ignored(self) -> None:
        info = analyze_url("https://polxa.example.com/")
        self.assertNotIn("URL_BRAND_SUBDOMAIN", info.rule_codes)

    def test_company_webmail_on_own_domain(self) -> None:
        info = analyze_url("https://outlook.firma.pl/owa/", sender_domain="firma.pl",
                           sender_authenticated=True)
        self.assertNotIn("URL_BRAND_SUBDOMAIN", info.rule_codes)
        info = analyze_url("https://outlook.firma.pl/owa/", sender_domain="firma.pl")
        self.assertIn("URL_BRAND_SUBDOMAIN", info.rule_codes)


if __name__ == "__main__":
    unittest.main()
