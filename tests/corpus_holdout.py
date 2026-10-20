"""Second synthetic corpus, written independently of the rules (holdout).

Typical phishing techniques not covered by corpus.py, plus legitimate mail
shapes that easily trigger false alarms. No real people's mail.
"""
from __future__ import annotations

import io
import zipfile

from corpus import GMAIL_RECEIVED, Case, _auth, message


def _zip(name: str, data: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(name, data)
    return buffer.getvalue()


def _auth_for(domain: str) -> str:
    return (
        f"Authentication-Results: mx.google.com; spf=pass smtp.mailfrom={domain}; "
        f"dkim=pass header.d={domain}; dmarc=pass header.from={domain}\n"
    )


PHISHING_HOLDOUT = [
    Case(
        "mailbox_full_compromised_site",
        message(
            _auth_for("piekarnia-kowalski.pl") + GMAIL_RECEIVED +
            'From: "Administrator poczty" <biuro@piekarnia-kowalski.pl>\n'
            "Subject: Twoja skrzynka jest pelna - dzialanie wymagane\n",
            html="<p>Twoja skrzynka pocztowa przekroczyla limit. Wiadomosci przychodzace "
                 "zostana zablokowane w ciagu 24 godzin. Zweryfikuj konto, aby zachowac dostep.</p>"
                 '<a href="https://piekarnia-kowalski.pl/wp-content/uploads/mail/login.php?u=jan">'
                 "Zweryfikuj teraz</a>",
        ),
        "SUSPICIOUS",
    ),
    Case(
        "brand_in_subject_workers_dev",
        message(
            _auth_for("mailer-7731.com") + GMAIL_RECEIVED +
            'From: "Support Team" <no-reply@mailer-7731.com>\n'
            "Subject: Microsoft 365: Your password expires today\n",
            html="<p>Your Microsoft 365 password expires today. Keep your current password "
                 "to avoid losing access.</p>"
                 '<a href="https://keep-pass-7731.workers.dev/">Keep current password</a>',
        ),
        "SUSPICIOUS",
    ),
    Case(
        "homoglyph_display_name_paypai",
        message(
            _auth_for("service-center.info") + GMAIL_RECEIVED +
            'From: "PayPaI" <service@service-center.info>\n'
            "Subject: Your account has been limited\n",
            html="<p>We noticed unusual activity. Your account has been suspended. "
                 "Confirm your identity to restore access.</p>"
                 '<a href="https://service-center.info/restore">Restore account</a>',
        ),
        "SUSPICIOUS",
    ),
    Case(
        "digit_display_name_allegr0",
        message(
            GMAIL_RECEIVED + 'From: "Allegr0 Pomoc" <pomoc@kontakt-sklep.eu>\n'
            "Subject: Platnosc nieudana\n",
            html="<p>Platnosc za zamowienie nie powiodla sie. Zaplac ponownie.</p>"
                 '<a href="https://kontakt-sklep.eu/zaplac">Zaplac</a>',
        ),
        "SUSPICIOUS",
    ),
    Case(
        "olx_short_brand_in_subdomain",
        message(
            _auth_for("bezpieczna-transakcja24.pl") + GMAIL_RECEIVED +
            'From: "Obsluga Klienta" <info@bezpieczna-transakcja24.pl>\n'
            "Subject: Kupujacy oplacil Twoj przedmiot\n",
            html="<p>Kupujacy oplacil zamowienie na OLX. Aby odebrac srodki, potwierdz dane karty.</p>"
                 '<a href="https://olx.bezpieczna-transakcja24.pl/odbierz">Odbierz srodki</a>',
        ),
        "SUSPICIOUS",
    ),
    Case(
        "brand_dot_pl_dash_domain",
        message(
            _auth_for("oferta-mail.com") + GMAIL_RECEIVED +
            'From: "Powiadomienia" <no-reply@oferta-mail.com>\n'
            "Subject: Twoje konto zostanie zawieszone\n",
            text="Zaloguj sie, aby potwierdzic dane: https://allegro.pl-weryfikacja.com/logowanie",
        ),
        "SUSPICIOUS",
    ),
    Case(
        "brand_in_subdomain_risky_tld",
        message(
            _auth_for("bank-info.net") + GMAIL_RECEIVED +
            'From: "Bank" <alert@bank-info.net>\nSubject: Nowe urzadzenie\n',
            html='<a href="https://mbank.pl.secure-login.top/">Potwierdz urzadzenie</a>',
        ),
        "SUSPICIOUS",
    ),
    Case(
        "parcel_shortener_plain_text",
        message(
            _auth_for("kurier-info.net") + GMAIL_RECEIVED +
            'From: "Kurier" <sms@kurier-info.net>\nSubject: Paczka wstrzymana\n',
            text="Twoja paczka zostala wstrzymana. Doplata 2,50 zl w ciagu 24 godzin: https://bit.ly/3xYzAbc",
        ),
        "SUSPICIOUS",
    ),
    Case(
        "ceo_fraud_freemail",
        message(
            _auth_for("gmail.com") + GMAIL_RECEIVED +
            'From: "Marek Nowak - Prezes" <marek.nowak.prezes@gmail.com>\n'
            "Reply-To: marek.prezes@protonmail.com\nSubject: Pilne - przelew\n",
            text="Potrzebuje pilnie zlecic przelew 48 500 zl na nowe konto kontrahenta. "
                 "Jestem na spotkaniu, nie dzwon. Potwierdz gdy zrobione.",
        ),
        "SUSPICIOUS",
    ),
    Case(
        "zip_with_javascript",
        message(
            _auth_for("biuro-rachunkowe.example.pl") + GMAIL_RECEIVED +
            "From: Faktury <faktury@biuro-rachunkowe.example.pl>\nSubject: Faktura korygujaca\n",
            text="W zalaczniku faktura korygujaca.",
            attachments=(("faktura.zip", "application/zip",
                          _zip("faktura_korekta.pdf.js", b"WScript.Shell")),),
        ),
        "DANGEROUS",
    ),
    Case(
        "qr_code_quishing",
        message(
            GMAIL_RECEIVED + 'From: "IT Helpdesk" <helpdesk@secure-mfa.online>\n'
            "Subject: Wymagana ponowna konfiguracja MFA\n",
            html="<p>Twoje uwierzytelnianie wieloskladnikowe wygasa dzisiaj. "
                 "Zeskanuj kod QR telefonem, aby zachowac dostep do poczty.</p>"
                 '<img src="cid:qr123">',
        ),
        "SUSPICIOUS",
    ),
    Case(
        "lnk_attachment",
        message(
            _auth_for("firma-transport.example.pl") + GMAIL_RECEIVED +
            "From: a@firma-transport.example.pl\nSubject: Dokumenty przewozowe\n",
            text="Dokumenty w zalaczniku.",
            attachments=(("Dokumenty.pdf.lnk", "application/octet-stream", b"L\x00\x00\x00\x01\x14\x02\x00"),),
        ),
        "DANGEROUS",
    ),
    Case(
        "gov_tax_refund_display_alias",
        message(
            GMAIL_RECEIVED + 'From: "Ministerstwo Finansow" <zwrot@podatki-zwrot.com>\n'
            "Subject: Zwrot podatku 1 247 zl\n",
            html='<p>Przysluguje Ci zwrot podatku. Podaj dane karty.</p>'
                 '<a href="https://podatki-zwrot.com/zwrot">Odbierz zwrot</a>',
        ),
        "DANGEROUS",
    ),
    Case(
        "ip_link_with_login",
        message(
            _auth_for("mail-service.example.net") + GMAIL_RECEIVED +
            "From: Security <security@mail-service.example.net>\nSubject: Unusual sign-in\n",
            html='<a href="http://185.12.33.4/office365/login.php">Review activity</a>',
        ),
        "SUSPICIOUS",
    ),
]


LEGITIMATE_HOLDOUT = [
    Case(
        "czech_engineer_title",
        message(
            _auth_for("firma.cz") + GMAIL_RECEIVED +
            'From: "Ing. Petr Novak" <petr.novak@firma.cz>\nSubject: Nabidka\n',
            text="Dobry den, posilam nabidku v priloze.",
        ),
        "SAFE",
    ),
    Case(
        "bank_security_warning_text",
        message(
            _auth_for("pkobp.pl") + GMAIL_RECEIVED +
            'From: "PKO Bank Polski" <powiadomienia@pkobp.pl>\nSubject: Uwazaj na oszustow\n',
            html="<p>Pamietaj: bank nigdy nie prosi o podanie hasla, kodu BLIK ani kodu SMS. "
                 "Nie loguj sie przez linki z wiadomosci. Zaloguj sie tylko przez aplikacje.</p>"
                 '<a href="https://www.pkobp.pl/bezpieczenstwo/">Dowiedz sie wiecej</a>',
        ),
        "SAFE",
    ),
    Case(
        "pko_leasing_subsidiary",
        message(
            _auth_for("pkoleasing.pl") + GMAIL_RECEIVED +
            'From: "PKO Leasing" <obsluga@pkoleasing.pl>\nSubject: Harmonogram rat\n',
            html='<a href="https://www.pkoleasing.pl/klient">Panel klienta</a>',
        ),
        "SAFE",
    ),
    Case(
        "google_groups_list",
        message(
            _auth_for("googlegroups.com") + GMAIL_RECEIVED +
            "From: \"'Jan Kowalski' via Klub Rowerowy\" <klub-rowerowy@googlegroups.com>\n"
            "Reply-To: jan.kowalski@example.pl\nSubject: Wyjazd w sobote\n",
            text="Hej, w sobote zbiorka o 9:00.",
        ),
        "SAFE",
    ),
    Case(
        "colleague_mentions_microsoft",
        message(
            _auth_for("firma.example.pl") + GMAIL_RECEIVED +
            'From: "Anna Wisniewska" <anna@firma.example.pl>\nSubject: Licencje Microsoft 365\n',
            text="Czesc, w przyszlym tygodniu odnawiamy licencje Microsoft 365. "
                 "Lista uzytkownikow: https://firma.example.pl/intranet/licencje",
        ),
        "SAFE",
    ),
    Case(
        "saas_password_reset_requested",
        message(
            _auth_for("notion.so") + GMAIL_RECEIVED +
            'From: "Notion" <notify@mail.notion.so>\nSubject: Reset your password\n',
            html="<p>Click the link below to reset your password. The link expires in 24 hours.</p>"
                 '<a href="https://www.notion.so/reset?token=abc">Reset password</a>',
        ),
        "SAFE",
    ),
    Case(
        "invoice_reminder_from_accountant",
        message(
            _auth_for("biuro-rachunkowe.example.pl") + GMAIL_RECEIVED +
            'From: "Biuro Rachunkowe Lex" <biuro@biuro-rachunkowe.example.pl>\n'
            "Reply-To: ksiegowa@lex-ksiegowosc.example.com\nSubject: Przypomnienie o fakturze\n",
            text="Dzien dobry, przypominamy o fakturze do zaplaty do 25.10. "
                 "Faktura w zalaczniku.",
            attachments=(("FV_10_2026.pdf", "application/pdf", b"%PDF-1.7\n1 0 obj<<>>endobj\n"),),
        ),
        "SAFE",
    ),
    Case(
        "microsoft_real_security_notice",
        message(
            _auth_for("accountprotection.microsoft.com") + GMAIL_RECEIVED +
            'From: "Microsoft account team" <account-security-noreply@accountprotection.microsoft.com>\n'
            "Subject: Microsoft account security code\n",
            html="<p>Please use the following security code for the Microsoft account. "
                 "If you didn't request this code, you can safely ignore this email.</p>"
                 '<a href="https://account.live.com/ResetPassword.aspx">reset your password</a>',
        ),
        "SAFE",
    ),
    Case(
        "newsletter_with_shortener_mention",
        message(
            _auth_for("blog.example.com") + GMAIL_RECEIVED +
            'From: "Tech Blog" <newsletter@blog.example.com>\nSubject: Nowy wpis\n',
            html='<p>Nowy artykul o bezpieczenstwie.</p>'
                 '<a href="https://blog.example.com/wpis/phishing-2026">Czytaj</a>',
        ),
        "SAFE",
    ),
    Case(
        "inpost_marketing_via_esp",
        message(
            "Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=bounce.sendgrid.net; "
            "dkim=pass header.d=inpost.pl; dmarc=pass header.from=inpost.pl\n" + GMAIL_RECEIVED +
            'From: "InPost" <newsletter@inpost.pl>\nReturn-Path: <b@bounce.sendgrid.net>\n'
            "Subject: Nowa funkcja w aplikacji\n",
            html='<a href="https://u123.ct.sendgrid.net/ls/click?upn=xyz">Sprawdz w aplikacji InPost</a>',
        ),
        "SAFE",
    ),
]
