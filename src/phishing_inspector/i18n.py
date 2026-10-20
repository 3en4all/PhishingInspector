"""All user-facing texts of the desktop app, in Polish and English.

One GUI module reads from here, so a change of layout or behaviour is made
once and both language builds get it.
"""
from __future__ import annotations

LANGUAGES = ("pl", "en")
DEFAULT_LANGUAGE = "pl"

TEXTS: dict[str, dict[str, str]] = {
    "pl": {
        "drop_here": "Upuść tutaj plik .eml lub .msg",
        "analyze": "Analizuj",
        "analyzing": "Analizuję...",
        "open_file": "Otwórz plik",
        "technical_log": "Log techniczny",
        "export_pdf": "Eksportuj PDF",
        "export_html": "Eksportuj HTML",
        "network_checks": "Sprawdź rekordy DNS nadawcy",
        "network_checks_tip": (
            "Wysyła zapytania DNS o rekordy SPF/DMARC domeny nadawcy. "
            "Właściciel tej domeny (np. oszust) może zobaczyć, że wiadomość "
            "była sprawdzana. Wynik jest tylko informacyjny i nie zmienia oceny."
        ),
        "result_card": "Wynik analizy",
        "no_analysis": "BRAK ANALIZY",
        "what_it_means": "Co to oznacza?",
        "file": "Plik:",
        "origin_ip": "IP nadawcy:",
        "verdict": "Werdykt:",
        "score": "Wynik:",
        "chip_score": "Wynik: {score}/100",
        "chip_urls": "Linki: {total} / podejrzane {suspicious}",
        "chip_attachments": "Załączniki: {total} / podejrzane {suspicious}",
        "verdict_safe": "BEZPIECZNY",
        "verdict_suspicious": "WYMAGA OSTROŻNOŚCI",
        "verdict_dangerous": "NIEBEZPIECZNY",
        "key_findings": "Najważniejsze ustalenia:",
        "feedback_group": "Czy wynik analizy jest poprawny?",
        "feedback_correct": "Wynik poprawny",
        "feedback_false_positive": "Fałszywy alarm",
        "feedback_phishing": "To był phishing",
        "feedback_unsure": "Nie jestem pewien",
        "feedback_save": "Wyślij ocenę wyniku",
        "feedback_tip": (
            "Wysyłane są: werdykt, wynik, kody reguł (np. URL_BRAND_IMITATION), "
            "wyniki SPF/DKIM/DMARC i wersja programu. Bez treści, tematu, adresów, "
            "linków i załączników."
        ),
        "feedback_sent": "Ocena wyniku przekazana do wysyłki. Lokalna kopia nie jest tworzona.",
        "tab_headers": "Nagłówki",
        "tab_auth": "Uwierzytelnienie",
        "tab_urls": "Linki",
        "tab_attachments": "Załączniki",
        "tab_findings": "Ustalenia",
        "field": "Pole",
        "value": "Wartość",
        "log_normal": "Podstawowy",
        "log_detailed": "Szczegółowy",
        "copy_log": "Kopiuj log",
        "log_copied": "Log techniczny skopiowany do schowka",
        "ready": "Gotowe",
        "file_selected": "Wybrano plik",
        "analysis_complete": "Analiza zakończona",
        "analysis_failed": "Analiza nie powiodła się",
        "analysis_error": "Błąd analizy",
        "invalid_file": "Nieprawidłowy plik",
        "not_a_file": "Wybrana ścieżka nie jest plikiem.",
        "unsupported_file": "Nieobsługiwany plik",
        "only_eml_msg": "Obsługiwane są tylko pliki .eml i .msg.",
        "select_email": "Wybierz plik wiadomości",
        "email_files": "Pliki e-mail (*.eml *.msg)",
        "export_pdf_title": "Eksport raportu PDF",
        "export_html_title": "Eksport raportu HTML",
        "pdf_exported": "Zapisano PDF: {path}",
        "html_exported": "Zapisano HTML: {path}",
        "no_warnings": "Brak ostrzeżeń",
        "host": "Host",
        "link_text": "Tekst linku",
        "source": "Źródło",
        "suspicious": "Podejrzany",
        "type": "Typ",
        "size": "Rozmiar",
        "bytes": "B",
        "what_it_means_prefix": "Co to znaczy:",
        "limitations": "Ograniczenia analizy:",
        "buycoffee_tip": "Jeśli Phishing Inspector Ci się przydaje, możesz wesprzeć rozwój projektu.",
        "buycoffee_asset": "buycoffee-button-primary.png",
        "rating_title": "Oceń Phishing Inspector",
        "rating_question": "Jak oceniasz Phishing Inspector?",
        "rating_info": "Kliknij liczbę gwiazdek. Wysyłana jest tylko ocena 1–5, bez danych z analizowanych wiadomości.",
        "rating_roadmap": (
            "<b>To dopiero beta.</b><br>"
            "W kolejnych wersjach planujemy rozbudować analizę techniczną "
            "oraz dodać nowe mechanizmy wykrywania zagrożeń. "
            "Po drodze pojawią się również mniejsze ulepszenia raportów i interfejsu."
        ),
        "not_now": "Nie teraz",
        "summary_safe": (
            "Ten e-mail wygląda na bezpieczny. "
            "Nie wykryto istotnych oznak phishingu ani innych silnych sygnałów zagrożenia. "
            "Mimo to zachowaj ostrożność, jeśli wiadomość była niespodziewana, "
            "prosi o podanie hasła, płatność albo pilne działanie."
        ),
        "summary_suspicious": (
            "Ten e-mail zawiera elementy wymagające ostrożności. "
            "Nie każdy wykryty sygnał oznacza phishing, ale przed kliknięciem linków "
            "lub otwarciem załączników warto potwierdzić nadawcę i kontekst wiadomości."
        ),
        "summary_dangerous": (
            "Ta wiadomość wykazuje silne oznaki phishingu lub innego zagrożenia. "
            "Nie klikaj linków, nie otwieraj załączników i nie odpowiadaj na tę wiadomość. "
            "Jeśli dotyczy firmy, banku lub usługi, skontaktuj się z nimi niezależnym kanałem."
        ),
        "bullet_auth": "Uwierzytelnianie nadawcy: {count}/3 mechanizmy SPF/DKIM/DMARC zakończone wynikiem PASS.",
        "bullet_links": "Linki: znaleziono {total}, z czego {suspicious} oznaczono jako podejrzane.",
        "bullet_no_links": "Linki: nie znaleziono adresów URL w treści wiadomości.",
        "bullet_attachments": "Załączniki: znaleziono {total}, z czego {suspicious} oznaczono jako podejrzane.",
        "bullet_archives": (
            "Archiwa/kontenery: {count}. Ich struktura może być sprawdzana statycznie, "
            "ale program nie uruchamia plików z archiwum."
        ),
        "bullet_attachment_warning": (
            "Wiadomość zawiera załącznik. Jeśli nie znasz nadawcy lub nie spodziewałeś się pliku, "
            "nie otwieraj go przed potwierdzeniem źródła wiadomości."
        ),
        "bullet_no_attachments": "Załączniki: brak.",
        "bullet_findings": "Najważniejsze sygnały: {count} wpis(y) w zakładce Ustalenia.",
        "bullet_top": "Główny powód: {reason}",
        "auth_dkim_domain": "Domena DKIM",
        "auth_spf_alignment": "Zgodność SPF",
        "auth_dkim_alignment": "Zgodność DKIM",
        "auth_server": "Serwer weryfikujący",
        "auth_ignored": "Pominięte nagłówki Authentication-Results",
        "auth_dns": "Rekordy DNS (SPF/DMARC)",
        "dns_disabled": "nie sprawdzano (wyłączone)",
        "log_privacy_start": "Analiza statyczna, lokalna. Zapytania DNS: {dns}.",
        "log_privacy_end": "Nie otwierano linków i nie uruchamiano załączników.",
        "on": "włączone",
        "off": "wyłączone",
    },
    "en": {
        "drop_here": "Drop .eml or .msg file here",
        "analyze": "Analyze",
        "analyzing": "Analyzing...",
        "open_file": "Open file",
        "technical_log": "Technical log",
        "export_pdf": "Export PDF",
        "export_html": "Export HTML",
        "network_checks": "Look up sender DNS records",
        "network_checks_tip": (
            "Sends DNS queries for the sender domain's SPF/DMARC records. "
            "The owner of that domain (possibly the attacker) may see that the "
            "message was checked. The result is informational and does not change the score."
        ),
        "result_card": "Analysis result",
        "no_analysis": "NO ANALYSIS",
        "what_it_means": "What does this mean?",
        "file": "File:",
        "origin_ip": "Originating IP:",
        "verdict": "Verdict:",
        "score": "Score:",
        "chip_score": "Score: {score}/100",
        "chip_urls": "URLs: {total} / suspicious {suspicious}",
        "chip_attachments": "Attachments: {total} / suspicious {suspicious}",
        "verdict_safe": "SAFE",
        "verdict_suspicious": "CAUTION ADVISED",
        "verdict_dangerous": "DANGEROUS",
        "key_findings": "Key findings:",
        "feedback_group": "Is the analysis result correct?",
        "feedback_correct": "Result is correct",
        "feedback_false_positive": "False positive",
        "feedback_phishing": "This was phishing",
        "feedback_unsure": "I am not sure",
        "feedback_save": "Submit feedback",
        "feedback_tip": (
            "Sent: verdict, score, rule codes (e.g. URL_BRAND_IMITATION), "
            "SPF/DKIM/DMARC results and app version. No body, subject, addresses, "
            "links or attachments."
        ),
        "feedback_sent": "Feedback queued for submission. No local copy is created.",
        "tab_headers": "Headers",
        "tab_auth": "Authentication",
        "tab_urls": "URLs",
        "tab_attachments": "Attachments",
        "tab_findings": "Findings",
        "field": "Field",
        "value": "Value",
        "log_normal": "Normal",
        "log_detailed": "Detailed",
        "copy_log": "Copy log",
        "log_copied": "Technical log copied to clipboard",
        "ready": "Ready",
        "file_selected": "File selected",
        "analysis_complete": "Analysis complete",
        "analysis_failed": "Analysis failed",
        "analysis_error": "Analysis error",
        "invalid_file": "Invalid file",
        "not_a_file": "Selected path is not a file.",
        "unsupported_file": "Unsupported file",
        "only_eml_msg": "Only .eml and .msg files are supported.",
        "select_email": "Select email file",
        "email_files": "Email files (*.eml *.msg)",
        "export_pdf_title": "Export PDF report",
        "export_html_title": "Export HTML report",
        "pdf_exported": "PDF exported: {path}",
        "html_exported": "HTML exported: {path}",
        "no_warnings": "No warnings",
        "host": "Host",
        "link_text": "Link text",
        "source": "Source",
        "suspicious": "Suspicious",
        "type": "Type",
        "size": "Size",
        "bytes": "bytes",
        "what_it_means_prefix": "What it means:",
        "limitations": "Analysis limitations:",
        "buycoffee_tip": "If Phishing Inspector is useful to you, you can support further development.",
        "buycoffee_asset": "buycoffee-button-primary-en.png",
        "rating_title": "Rate Phishing Inspector",
        "rating_question": "How would you rate Phishing Inspector?",
        "rating_info": "Click the number of stars. Only the 1–5 rating is sent, without any data from analyzed messages.",
        "rating_roadmap": (
            "<b>This is still a beta.</b><br>"
            "Future releases will expand the technical analysis "
            "and add new threat-detection mechanisms. "
            "Smaller improvements to reports and the interface will also be introduced along the way."
        ),
        "not_now": "Not now",
        "summary_safe": (
            "This email appears safe. "
            "No significant phishing indicators or other strong threat signals were detected. "
            "Still, remain cautious if the message was unexpected, "
            "asks for a password, payment, or urgent action."
        ),
        "summary_suspicious": (
            "This email contains elements that require caution. "
            "Not every detected signal means phishing, but before clicking links "
            "or opening attachments, verify the sender and the context of the message."
        ),
        "summary_dangerous": (
            "This message shows strong signs of phishing or another threat. "
            "Do not click links, open attachments, or reply to this message. "
            "If it concerns a company, bank, or online service, contact them through an independent trusted channel."
        ),
        "bullet_auth": "Sender authentication: {count}/3 SPF/DKIM/DMARC mechanisms returned PASS.",
        "bullet_links": "Links: {total} found, {suspicious} marked as suspicious.",
        "bullet_no_links": "Links: no URLs were found in the message body.",
        "bullet_attachments": "Attachments: {total} found, {suspicious} marked as suspicious.",
        "bullet_archives": (
            "Archives/containers: {count}. Their structure may be inspected statically, "
            "but the application does not execute files from archives."
        ),
        "bullet_attachment_warning": (
            "The message contains an attachment. If you do not know the sender or were not expecting a file, "
            "do not open it until you have confirmed the source of the message."
        ),
        "bullet_no_attachments": "Attachments: none.",
        "bullet_findings": "Key indicators: {count} item(s) in the Findings tab.",
        "bullet_top": "Main reason: {reason}",
        "auth_dkim_domain": "DKIM domain",
        "auth_spf_alignment": "SPF alignment",
        "auth_dkim_alignment": "DKIM alignment",
        "auth_server": "Verifying server",
        "auth_ignored": "Ignored Authentication-Results headers",
        "auth_dns": "DNS records (SPF/DMARC)",
        "dns_disabled": "not checked (disabled)",
        "log_privacy_start": "Static local analysis. DNS lookups: {dns}.",
        "log_privacy_end": "No links opened and no attachments executed.",
        "on": "on",
        "off": "off",
    },
}

AUTH_VALUES: dict[str, dict[str, dict[str, str]]] = {
    "pl": {
        "SPF": {
            "pass": "PASS — serwer wysyłający został potwierdzony przez SPF",
            "fail": "FAIL — SPF nie potwierdził serwera wysyłającego",
            "softfail": "SOFTFAIL — SPF zgłasza słabą niezgodność",
            "neutral": "NEUTRAL — SPF nie daje jednoznacznego wyniku",
            "none": "BRAK — domena nie przekazała wyniku SPF",
            "unknown": "NIEZNANY — brak wystarczających danych SPF",
            "_other": "{value} — wynik SPF",
        },
        "DKIM": {
            "pass": "PASS — podpis DKIM wiadomości jest prawidłowy",
            "fail": "FAIL — podpis DKIM nie przeszedł weryfikacji",
            "none": "BRAK — nie znaleziono prawidłowego wyniku DKIM",
            "unknown": "NIEZNANY — brak wystarczających danych DKIM",
            "_other": "{value} — wynik DKIM",
        },
        "DMARC": {
            "pass": "PASS — domena nadawcy przeszła kontrolę DMARC",
            "fail": "FAIL — domena nadawcy nie przeszła kontroli DMARC",
            "none": "BRAK — brak jednoznacznego wyniku DMARC",
            "unknown": "NIEZNANY — brak wystarczających danych DMARC",
            "_other": "{value} — wynik DMARC",
        },
        "SPF aligned": {
            "true": "TAK — domena technicznego nadawcy jest zgodna z domeną From",
            "false": "NIE — domena technicznego nadawcy różni się od domeny From",
            "none": "NIEZNANE — brak danych do porównania domen",
        },
        "DKIM aligned": {
            "true": "TAK — domena podpisu DKIM jest zgodna z domeną From",
            "false": "NIE — domena podpisu DKIM różni się od domeny From",
            "none": "NIEZNANE — brak danych do porównania domen",
        },
        "DKIM domain": {"_other": "{value} — domena użyta do podpisania wiadomości", "empty": "brak"},
    },
    "en": {
        "SPF": {
            "pass": "PASS — the sending server is authorized by SPF",
            "fail": "FAIL — SPF did not authorize the sending server",
            "softfail": "SOFTFAIL — SPF reports a weak mismatch",
            "neutral": "NEUTRAL — SPF does not provide a definitive result",
            "none": "NONE — no SPF result was provided for the domain",
            "unknown": "UNKNOWN — insufficient SPF data",
            "_other": "{value} — SPF result",
        },
        "DKIM": {
            "pass": "PASS — the message DKIM signature is valid",
            "fail": "FAIL — the DKIM signature failed verification",
            "none": "NONE — no valid DKIM result was found",
            "unknown": "UNKNOWN — insufficient DKIM data",
            "_other": "{value} — DKIM result",
        },
        "DMARC": {
            "pass": "PASS — the sender domain passed DMARC validation",
            "fail": "FAIL — the sender domain failed DMARC validation",
            "none": "NONE — no definitive DMARC result",
            "unknown": "UNKNOWN — insufficient DMARC data",
            "_other": "{value} — DMARC result",
        },
        "SPF aligned": {
            "true": "YES — the technical sender domain aligns with the From domain",
            "false": "NO — the technical sender domain differs from the From domain",
            "none": "UNKNOWN — insufficient data to compare domains",
        },
        "DKIM aligned": {
            "true": "YES — the DKIM signing domain aligns with the From domain",
            "false": "NO — the DKIM signing domain differs from the From domain",
            "none": "UNKNOWN — insufficient data to compare domains",
        },
        "DKIM domain": {"_other": "{value} — domain used to sign the message", "empty": "none"},
    },
}

# (keywords that must all appear in the lower-cased reason, pl text, en text).
# First match wins, so specific entries come before general ones.
EXPLANATIONS: tuple[tuple[tuple[str, ...], str, str], ...] = (
    (("context only",),
     "Informacja pomocnicza — nie podniosła oceny ryzyka.",
     "Context only — it did not raise the risk score."),
    (("forged authentication header",),
     "Ktoś dopisał do wiadomości fałszywy nagłówek z wynikiem „pass”. Prawdziwy serwer poczty tego nie potwierdził — to celowe oszustwo.",
     "Someone added a fake header claiming a \"pass\". The real mail server did not confirm it — this is deliberate deception."),
    (("sender name impersonates",),
     "Nazwa nadawcy podaje się za znaną firmę, ale adres e-mail jest z obcej domeny. To najczęstszy sposób podszywania się.",
     "The sender name claims to be a well-known company, but the email address is from an unrelated domain. This is the most common impersonation trick."),
    (("link text shows a different site",),
     "Tekst linku pokazuje jeden adres, a kliknięcie prowadzi pod inny. Tak ukrywa się prawdziwy cel linku.",
     "The link text shows one address, but clicking it opens another. This is how the real destination is hidden."),
    (("link domain imitates",),
     "Link prowadzi do domeny podszywającej się pod znaną markę (literówka, podmienione znaki albo nazwa marki w obcej domenie).",
     "The link goes to a domain imitating a well-known brand (typo, swapped characters or the brand name in a foreign domain)."),
    (("javascript:/data:",),
     "Link zamiast strony uruchamia skrypt lub zawiera ukrytą stronę. Zwykłe wiadomości tak nie robią.",
     "The link runs a script or carries a hidden page instead of opening a website. Normal emails do not do this."),
    (("redirects to a suspicious",),
     "Link przechodzi przez przekierowanie, które kończy się na podejrzanym adresie.",
     "The link passes through a redirect that ends at a suspicious address."),
    (("no spf, dkim or dmarc",),
     "Wiadomość używa nazwy znanej marki, a nie ma żadnego potwierdzenia nadawcy (SPF/DKIM/DMARC).",
     "The message uses a well-known brand but has no sender confirmation at all (SPF/DKIM/DMARC)."),
    (("phishing pressure",),
     "Treść naciska na szybkie działanie, płatność lub podanie danych logowania — typowe dla phishingu.",
     "The text pushes for quick action, payment or login details — typical for phishing."),
    (("web page attachment with a form",),
     "Załącznik to strona WWW z formularzem, polem hasła lub skryptem. Po otwarciu może pokazać fałszywe logowanie.",
     "The attachment is a web page with a form, password field or script. Opened, it can show a fake login page."),
    (("web page / svg",),
     "Załącznik HTML/SVG otwiera się w przeglądarce. Firmy rzadko tak wysyłają dokumenty; oszuści często.",
     "An HTML/SVG attachment opens in the browser. Companies rarely send documents this way; scammers often do."),
    (("disk image",),
     "Obraz dysku (ISO/IMG/VHD) może ukryć program przed ostrzeżeniami Windows.",
     "A disk image (ISO/IMG/VHD) can hide a program from Windows security warnings."),
    (("pdf with active content",),
     "PDF zawiera JavaScript, akcję uruchamiania lub osadzony plik.",
     "The PDF contains JavaScript, a launch action or an embedded file."),
    (("password-protected archive",),
     "Archiwum na hasło nie mogło zostać sprawdzone przez filtry poczty. To częsty sposób przemycania złośliwych plików.",
     "A password-protected archive could not be scanned by mail filters. It is a common way to smuggle malware."),
    (("sender identity alignment mismatch",),
     "Adres nadawcy i domena techniczna nie są zgodne. Może to oznaczać podszywanie się.",
     "The visible sender address and the technical sending domain do not align. This may indicate sender impersonation."),
    (("lookalike or impersonation domain",),
     "Wykryto domenę podobną do znanej marki, co jest typową techniką phishingową.",
     "A domain similar to a known brand was detected. Lookalike domains are a common phishing technique."),
    (("sender domain uses punycode",),
     "Domena nadawcy zawiera znaki spoza alfabetu łacińskiego, które mogą udawać zwykłe litery.",
     "The sender domain uses non-Latin characters that can imitate ordinary letters."),
    (("spf", "fail"),
     "SPF nie potwierdził serwera wysyłającego. Może to wskazywać na spoofing.",
     "SPF did not authorize the sending server. This may indicate email spoofing."),
    (("dkim", "fail"),
     "Podpis DKIM nie przeszedł weryfikacji. Wiadomość lub podpis mogą być nieprawidłowe.",
     "The DKIM signature failed verification. The message or its signature may be invalid or altered."),
    (("dmarc", "fail"),
     "DMARC nie został spełniony. To silny sygnał możliwego podszywania się.",
     "DMARC validation failed. This is a strong indicator of possible sender impersonation."),
    (("suspicious url indicators",),
     "Co najmniej jeden link ma cechy często spotykane w phishingu.",
     "At least one link has characteristics commonly associated with phishing."),
    (("dangerous attachment",),
     "Załącznik może uruchamiać kod i nie powinien być otwierany bez dodatkowej analizy.",
     "The attachment may be capable of executing code and should not be opened without additional analysis."),
    (("macro-enabled attachment",),
     "Dokument może zawierać makra, które bywają używane do uruchamiania złośliwego kodu.",
     "The document may contain macros, which can be abused to execute malicious code."),
    (("delivery-chain anomaly",),
     "Łańcuch serwerów Received wygląda nietypowo lub jest niepełny.",
     "The Received-header delivery chain appears unusual or incomplete."),
    (("no currently implemented high-risk indicators detected",),
     "Nie znaleziono istotnych sygnałów phishingu w obecnie zaimplementowanych regułach.",
     "No significant phishing indicators were detected by the currently implemented rules."),
)

DEFAULT_EXPLANATION = {
    "pl": "To zdarzenie miało wpływ na końcową ocenę ryzyka wiadomości.",
    "en": "This finding contributed to the message's final risk assessment.",
}


def normalize_language(language: str | None) -> str:
    language = (language or DEFAULT_LANGUAGE).lower()[:2]
    return language if language in LANGUAGES else DEFAULT_LANGUAGE


def text(language: str, key: str, **values) -> str:
    template = TEXTS[normalize_language(language)][key]
    return template.format(**values) if values else template


def explain_finding(reason: str, language: str = DEFAULT_LANGUAGE) -> str:
    language = normalize_language(language)
    lower = reason.lower()

    for keywords, pl, en in EXPLANATIONS:
        if all(keyword in lower for keyword in keywords):
            return pl if language == "pl" else en

    return DEFAULT_EXPLANATION[language]


def friendly_auth_value(language: str, field: str, value) -> str:
    table = AUTH_VALUES[normalize_language(language)].get(field)

    if table is None:
        return str(value)

    if field in {"SPF aligned", "DKIM aligned"}:
        key = "true" if value is True else "false" if value is False else "none"
        return table[key]

    if field == "DKIM domain":
        return table["_other"].format(value=value or table["empty"])

    normalized = str(value).strip().lower() if value is not None else "unknown"
    if normalized in table:
        return table[normalized]
    return table["_other"].format(value=str(value).upper())
