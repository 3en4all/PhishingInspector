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


class IpLinkTests(unittest.TestCase):
    def test_ip_link_scores(self) -> None:
        from phishing_inspector.scoring import score_analysis_detailed

        info = analyze_url("http://185.12.33.4/office365/login.php")
        score, verdict, _, findings = score_analysis_detailed(None, [info], [])
        self.assertIn("URL_IP_HOST", [f.code for f in findings])
        self.assertEqual(verdict, "SUSPICIOUS")

    def test_local_network_ip_is_context(self) -> None:
        info = analyze_url("http://192.168.1.50/")
        self.assertNotIn("URL_IP_HOST", info.rule_codes)


class ReplyToFreemailTests(unittest.TestCase):
    def _spoofing(self, headers: str):
        from email import message_from_string

        from phishing_inspector.spoofing import analyze_spoofing

        return analyze_spoofing(message_from_string(headers + "\n\nx"))

    def test_reply_to_other_free_mailbox(self) -> None:
        result = self._spoofing("From: Prezes <prezes.firmy@gmail.com>\n"
                                "Reply-To: prezes@protonmail.com")
        self.assertIn("SENDER_REPLY_TO_FREEMAIL", result.codes)

    def test_reply_to_same_or_company_address(self) -> None:
        for headers in ("From: a@gmail.com\nReply-To: b@gmail.com",
                        "From: a@firma.pl\nReply-To: b@firma.pl",
                        "From: lista@googlegroups.com\nReply-To: jan@firma.pl"):
            with self.subTest(headers):
                self.assertNotIn("SENDER_REPLY_TO_FREEMAIL", self._spoofing(headers).codes)


class ContentTests(unittest.TestCase):
    def test_business_email_compromise_phrases(self) -> None:
        from phishing_inspector.content_analysis import analyze_content

        result = analyze_content("Pilne", "Prosze zlecic przelew na nowe konto kontrahenta.")
        self.assertEqual(set(result.categories), {"urgency", "payment"})

    def test_qr_code_needs_another_lure(self) -> None:
        from phishing_inspector.content_analysis import analyze_content
        from phishing_inspector.scoring import score_analysis_detailed

        alone = analyze_content("Bilet", "Zeskanuj kod QR przy wejsciu.")
        pressured = analyze_content("MFA", "Zeskanuj kod QR, aby zachowac dostep do poczty.")
        codes = lambda c: [f.code for f in score_analysis_detailed(None, [], [], content=c)[3]]
        self.assertNotIn("CONTENT_QR_LURE", codes(alone))
        self.assertIn("CONTENT_QR_LURE", codes(pressured))


class HackedSitePathTests(unittest.TestCase):
    def test_login_page_in_cms_folder(self) -> None:
        for url in ("https://piekarnia.pl/wp-content/uploads/mail/login.php?u=1",
                    "https://firma.pl/.well-known/office365/verify.html"):
            with self.subTest(url):
                self.assertIn("URL_HACKED_SITE_PATH", analyze_url(url).rule_codes)

    def test_ordinary_cms_links(self) -> None:
        for url in ("https://firma.pl/wp-content/uploads/2026/10/cennik.pdf",
                    "https://moja-strona.pl/wp-login.php",
                    "https://moja-strona.pl/wp-admin/update-core.php",
                    "https://sklep.pl/images/logo.png"):
            with self.subTest(url):
                self.assertNotIn("URL_HACKED_SITE_PATH", analyze_url(url).rule_codes)


if __name__ == "__main__":
    unittest.main()
