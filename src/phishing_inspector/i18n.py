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
        "app_subtitle": "Analiza podejrzanych wiadomości e-mail  ·  3EN4ALL",
        "header_help": "Pomoc / O programie",
        "accent_tip": "Kolor akcentu: {name}",
        "drop_hint": "lub kliknij „Otwórz plik”. Analiza działa lokalnie na Twoim komputerze.",
        "drop_change": "Upuść inny plik, aby go zmienić",
        "result_card": "Wynik analizy",
        "no_analysis": "BRAK ANALIZY",
        "what_it_means": "Co to oznacza?",
        "verdict_safe": "BEZPIECZNY",
        "verdict_suspicious": "WYMAGA OSTROŻNOŚCI",
        "verdict_dangerous": "NIEBEZPIECZNY",
        "verdict_none_sub": "Wybierz wiadomość .eml lub .msg, aby zobaczyć ocenę ryzyka.",
        "verdict_safe_sub": "Nie wykryto istotnych oznak phishingu.",
        "verdict_suspicious_sub": "Wykryto sygnały, które warto sprawdzić przed kliknięciem.",
        "verdict_dangerous_sub": "Silne oznaki phishingu. Nie klikaj linków i nie otwieraj załączników.",
        "risk_score": "Wskaźnik ryzyka",
        "tile_links": "Linki",
        "tile_attachments": "Załączniki",
        "tile_origin_ip": "IP nadawcy",
        "tile_suspicious": "podejrzane: {count}",
        "tile_none": "brak",
        "tile_ip_sub": "pierwszy serwer w łańcuchu",
        "auth_sub_spf": "serwer nadawcy",
        "auth_sub_dkim": "podpis wiadomości",
        "auth_sub_dmarc": "polityka domeny",
        "auth_short_pass": "Zaliczony",
        "auth_short_fail": "Niezaliczony",
        "auth_short_softfail": "Częściowo",
        "auth_short_neutral": "Neutralny",
        "auth_short_none": "Brak",
        "auth_short_unknown": "Nieznany",
        "key_findings": "Najważniejsze ustalenia",
        "findings_placeholder": "Tu pojawi się wyjaśnienie wyniku i lista najważniejszych ustaleń.",
        "yes": "tak",
        "no": "nie",
        "technical_detail": "Szczegół techniczny",
        "branding": "Phishing Inspector  ·  3EN4ALL",
        "feedback_toggle": "Oceń trafność wyniku",
        "feedback_group": "Czy wynik analizy jest poprawny?",
        "feedback_correct": "Wynik poprawny",
        "feedback_false_positive": "Fałszywy alarm",
        "feedback_phishing": "To był phishing",
        "feedback_unsure": "Nie jestem pewien",
        "feedback_save": "Wyślij ocenę",
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
        "menu_help": "Pomoc",
        "menu_about": "O programie",
        "about_window_title": "Phishing Inspector — O programie",
        "about_badges": "Bezpłatny  •  v{version}  •  Windows",
        "about_tagline": "Analiza podejrzanych wiadomości e-mail",
        "about_description": (
            "Bezpłatne narzędzie od 3EN4ALL do sprawdzania plików .eml i .msg. "
            "Ocenia linki, nadawcę, załączniki i treść wiadomości, wyjaśnia "
            "wykryte sygnały phishingu i pozwala zapisać raport. Analiza działa "
            "lokalnie; połączenie z siecią następuje tylko po włączeniu opcji "
            "sprawdzania DNS."
        ),
        "about_project_title": "Projekt i dokumentacja",
        "about_link_site": "Oficjalna strona",
        "about_link_ecosystem": "Ekosystem 3EN4ALL",
        "about_link_github": "GitHub — kod i zgłoszenia",
        "about_link_privacy": "Polityka prywatności",
        "about_community_title": "Społeczność 3EN4ALL",
        "about_link_facebook": "Facebook",
        "about_link_youtube": "YouTube",
        "about_support_title": "Wesprzyj rozwój",
        "about_support_text": (
            "Program jest i pozostanie bezpłatny. Jeśli chcesz, możesz "
            "dobrowolnie wesprzeć rozwój projektów 3EN4ALL."
        ),
        "about_support_link": "Postaw kawę (buycoffee.to)",
        "about_disclaimer": (
            "Narzędzie wspomaga ocenę ryzyka, ale nie gwarantuje wykrycia "
            "wszystkich zagrożeń. W razie wątpliwości nie klikaj linków i nie "
            "otwieraj załączników."
        ),
        "about_footer": "© 2026 3EN4ALL  •  Rdzeń programu: licencja MIT",
        "about_close": "Zamknij",
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
        "app_subtitle": "Suspicious e-mail analysis  ·  3EN4ALL",
        "header_help": "Help / About",
        "accent_tip": "Accent colour: {name}",
        "drop_hint": "or click “Open file”. Analysis runs locally on your computer.",
        "drop_change": "Drop another file to replace it",
        "result_card": "Analysis result",
        "no_analysis": "NO ANALYSIS",
        "what_it_means": "What does this mean?",
        "verdict_safe": "SAFE",
        "verdict_suspicious": "CAUTION ADVISED",
        "verdict_dangerous": "DANGEROUS",
        "verdict_none_sub": "Choose an .eml or .msg message to see its risk rating.",
        "verdict_safe_sub": "No significant signs of phishing were found.",
        "verdict_suspicious_sub": "Some signals are worth checking before you click.",
        "verdict_dangerous_sub": "Strong signs of phishing. Do not click links or open attachments.",
        "risk_score": "Risk score",
        "tile_links": "Links",
        "tile_attachments": "Attachments",
        "tile_origin_ip": "Origin IP",
        "tile_suspicious": "suspicious: {count}",
        "tile_none": "none",
        "tile_ip_sub": "first server in the chain",
        "auth_sub_spf": "sending server",
        "auth_sub_dkim": "message signature",
        "auth_sub_dmarc": "domain policy",
        "auth_short_pass": "Pass",
        "auth_short_fail": "Fail",
        "auth_short_softfail": "Softfail",
        "auth_short_neutral": "Neutral",
        "auth_short_none": "None",
        "auth_short_unknown": "Unknown",
        "key_findings": "Key findings",
        "findings_placeholder": "The explanation of the result and the key findings will appear here.",
        "yes": "yes",
        "no": "no",
        "technical_detail": "Technical detail",
        "branding": "Phishing Inspector  ·  3EN4ALL",
        "feedback_toggle": "Rate this result",
        "feedback_group": "Is the analysis result correct?",
        "feedback_correct": "Result is correct",
        "feedback_false_positive": "False positive",
        "feedback_phishing": "This was phishing",
        "feedback_unsure": "I am not sure",
        "feedback_save": "Send",
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
        "menu_help": "Help",
        "menu_about": "About",
        "about_window_title": "About Phishing Inspector",
        "about_badges": "Free  •  v{version}  •  Windows",
        "about_tagline": "Analysis of suspicious e-mail messages",
        "about_description": (
            "A free tool by 3EN4ALL for checking .eml and .msg files. It "
            "examines links, the sender, attachments and message content, "
            "explains the phishing signals it finds and lets you save a report. "
            "Analysis runs locally; the network is used only when you turn on "
            "the DNS check option."
        ),
        "about_project_title": "Project and documentation",
        "about_link_site": "Official website",
        "about_link_ecosystem": "3EN4ALL ecosystem",
        "about_link_github": "GitHub — code and issues",
        "about_link_privacy": "Privacy policy",
        "about_community_title": "3EN4ALL community",
        "about_link_facebook": "Facebook",
        "about_link_youtube": "YouTube",
        "about_support_title": "Support development",
        "about_support_text": (
            "The program is and will stay free. If you like, you can "
            "voluntarily support the development of 3EN4ALL projects."
        ),
        "about_support_link": "Buy a coffee (buycoffee.to)",
        "about_disclaimer": (
            "This tool helps assess risk but does not guarantee that every "
            "threat is detected. When in doubt, do not click links or open "
            "attachments."
        ),
        "about_footer": "© 2026 3EN4ALL  •  Program core: MIT License",
        "about_close": "Close",
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
    (("brand name in front of someone else",),
     "Nazwa marki stoi na początku cudzej domeny (np. mbank.pl.oszust.top). Prawdziwa domena to ta na końcu adresu.",
     "A brand name is placed in front of someone else's domain (e.g. mbank.pl.scam.top). The real domain is the one at the end."),
    (("bare ip address",),
     "Link prowadzi na sam adres IP zamiast nazwy domeny. Firmy praktycznie tak nie linkują.",
     "The link points to a bare IP address instead of a domain name. Companies practically never link like this."),
    (("free mailbox",),
     "Odpowiedź trafi na darmową skrzynkę (np. Gmail), a nie na adres nadawcy. Tak działają oszustwa „na prezesa” i na fakturę.",
     "Replies go to a free mailbox (e.g. Gmail), not to the sender's address. This is how CEO and invoice fraud works."),
    (("scan a qr code",),
     "Wiadomość każe zeskanować kod QR pod presją. Link w obrazku omija filtry poczty i otwiera się na telefonie.",
     "The message urges you to scan a QR code. A link inside an image bypasses mail filters and opens on your phone."),
    (("asks for login details, but neither",),
     "Temat dotyczy znanej marki, ale ani nadawca, ani linki do niej nie należą, a wiadomość prosi o logowanie.",
     "The subject is about a known brand, but neither the sender nor the links belong to it, and the message asks you to log in."),
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
