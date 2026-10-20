"""More synthetic cases (0.3.1): phishing techniques missing from corpus.py
and legitimate mail shapes that easily trigger false alarms.

The first batch was written before the 0.3.1 rules and showed 9 of 14
phishing cases as SAFE and 2 false alarms. The second batch was written
after the rules, as a fresh check. No real people's mail.
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


PHISHING_MORE = [
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


LEGITIMATE_MORE = [
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


def _a(domain: str) -> str:
    return _auth_for(domain) + GMAIL_RECEIVED


# Second batch: written after the rules, as a fresh check.
PHISHING_MORE += [
    Case("dhl_customs_risky_tld", message(_a("post-service.click")+'From: "Customs Service" <info@post-service.click>\nSubject: Shipment on hold: customs fee\n', html='<p>Your DHL parcel is on hold. Pay the customs fee within 24 hours.</p><a href="https://dhl-express.post-service.click/pay">Pay now</a>'),"SUSPICIOUS"),
    Case("sharepoint_lure_onmicrosoft", message(_a("contoso-hr.onmicrosoft.com")+'From: "HR Department" <hr@contoso-hr.onmicrosoft.com>\nSubject: Salary adjustment 2026\n', html='<p>Sign in to view your salary adjustment document. Action required.</p><a href="https://contoso-hr.sharepoint.com/:b:/g/doc">View document</a>'),"SUSPICIOUS"),
    Case("netflix_payment_display", message(_a("billing-update.net")+'From: "Netflix" <billing@billing-update.net>\nSubject: Payment failed\n', html='<p>Update your payment details.</p><a href="https://billing-update.net/nf">Update</a>'),"SUSPICIOUS"),
    Case("vinted_short_link", message(GMAIL_RECEIVED+'From: "Vinted Support" <support@vinted-help.com>\nSubject: Odbierz platnosc\n', html='<a href="https://cutt.ly/abc">Odbierz srodki</a>'),"DANGEROUS"),
    Case("iso_attachment", message(_a("logistics.example.net")+'From: a@logistics.example.net\nSubject: Shipping documents\n', text="See attached.", attachments=(("documents.iso","application/octet-stream",b"\x00"*64),)),"SUSPICIOUS"),
    Case("pko_cyrillic_domain_link", message(_a("bank-alerts.net")+'From: "Bank Alerts" <alerts@bank-alerts.net>\nSubject: Logowanie z nowego urzadzenia\n', html='<a href="https://xn--pkob-j6d.pl/logowanie">Zaloguj sie</a>'),"SUSPICIOUS"),
]

LEGITIMATE_MORE += [
    Case("wordpress_notice", message(_a("moja-strona.pl")+'From: "WordPress" <wordpress@moja-strona.pl>\nSubject: [Moja strona] Dostepna aktualizacja\n', text="Zaloguj sie do kokpitu: https://moja-strona.pl/wp-admin/update-core.php"),"SAFE"),
    Case("teams_invite", message(_a("microsoft.com")+'From: "Microsoft Teams" <noreply@email.teams.microsoft.com>\nSubject: Jan zaprosil Cie do zespolu\n', html='<a href="https://teams.microsoft.com/l/team/abc">Otworz Microsoft Teams</a>'),"SAFE"),
    Case("reseller_m365_offer", message(_a("it-partner.example.pl")+'From: "IT Partner" <oferty@it-partner.example.pl>\nSubject: Microsoft 365 Business - nowe ceny od listopada\n', html='<p>Zaloguj sie do panelu partnera, aby zamowic licencje. Oferta wygasa dzisiaj.</p><a href="https://panel.it-partner.example.pl/login">Panel</a>'),"SAFE"),
    Case("invoice_saas_reply_gmail", message(_a("fakturownia.pl")+'From: "Jan Malinowski" <powiadomienia@fakturownia.pl>\nReply-To: jan.malinowski.serwis@gmail.com\nSubject: Faktura FV 12/10/2026\n', html='<p>Faktura do zaplaty w terminie 14 dni.</p><a href="https://janserwis.fakturownia.pl/invoice/abc">Pobierz fakture</a>'),"SAFE"),
    Case("olx_real_message", message(_a("olx.pl")+'From: "OLX" <powiadomienia@olx.pl>\nSubject: Masz nowa wiadomosc\n', html='<a href="https://www.olx.pl/d/mojolx/wiadomosci">Zobacz wiadomosc</a>'),"SAFE"),
    Case("it_printer_internal", message(_a("firma.example.pl")+'From: "Dzial IT" <it@firma.example.pl>\nSubject: Nowa drukarka\n', text="Panel drukarki: http://192.168.10.25/ - prosimy o zmiane hasla przy pierwszym logowaniu."),"SAFE"),
    Case("event_ticket_qr", message(_a("bilety.example.pl")+'From: "Bilety" <bilety@bilety.example.pl>\nSubject: Twoj bilet na koncert\n', html='<p>Zeskanuj kod QR przy wejsciu. Do zobaczenia!</p><img src="cid:qr">'),"SAFE"),
    Case("linkedin_jobs", message(_a("linkedin.com")+'From: "LinkedIn Job Alerts" <jobalerts-noreply@linkedin.com>\nSubject: 12 nowych ofert\n', html='<a href="https://www.linkedin.com/comm/jobs/view/123">Python Developer</a>'),"SAFE"),
    Case("payu_confirmation", message(_a("payu.pl")+'From: "PayU" <powiadomienia@payu.pl>\nSubject: Potwierdzenie platnosci BLIK\n', html='<p>Platnosc BLIK na kwote 120,00 zl zostala zrealizowana.</p><a href="https://www.payu.pl/pomoc">Pomoc</a>'),"SAFE"),
    Case("dpd_tracking", message(_a("dpd.com.pl")+'From: "DPD Polska" <powiadomienia@dpd.com.pl>\nSubject: Twoja paczka jest w drodze\n', html='<a href="https://tracktrace.dpd.com.pl/parcelDetails?p1=123">Sledz paczke</a>'),"SAFE"),
    Case("gov_mobywatel", message(_a("gov.pl")+'From: "mObywatel" <powiadomienia@mobywatel.gov.pl>\nSubject: Nowy dokument w aplikacji\n', html='<a href="https://www.gov.pl/web/mobywatel">gov.pl</a>'),"SAFE"),
    Case("friend_gmail_reply_onet", message(_a("gmail.com")+'From: "Kasia" <kasia.nowak@gmail.com>\nReply-To: kasia.nowak@onet.pl\nSubject: Zdjecia z wakacji\n', text="Hej, wysylam link do zdjec: https://photos.app.goo.gl/abc"),"SAFE"),
    Case("company_webmail_link", message(_a("firma.example.pl")+'From: "IT" <it@firma.example.pl>\nSubject: Nowy adres poczty\n', text="Poczta przez przegladarke: https://outlook.firma.example.pl/owa/ - zaloguj sie swoim haslem."),"SAFE"),
    Case("bank_blik_info", message(_a("mbank.pl")+'From: "mBank" <kontakt@mbank.pl>\nSubject: Nowosc: przelew na telefon BLIK\n', html='<p>Wyslij przelew na telefon przez BLIK. Zaloguj sie w aplikacji.</p><a href="https://www.mbank.pl/blik/">Wiecej</a>'),"SAFE"),
]
