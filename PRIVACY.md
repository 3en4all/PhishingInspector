# Polityka prywatności / Privacy policy — Phishing Inspector

_Ostatnia zmiana / Last updated: 2026-10-20_

## Polski

Phishing Inspector analizuje wiadomości e-mail **lokalnie na Twoim komputerze**. Treść wiadomości, temat, adresy nadawcy i odbiorców, linki, załączniki i ścieżki plików **nie są nigdzie wysyłane**.

**Co może zostać wysłane (tylko gdy sam klikniesz):**
- **Ocena wyniku skanu** („trafne”, „fałszywy alarm”, „potwierdzony phishing”, „nie wiem”): werdykt, wynik punktowy, kody reguł, które zadziałały (np. `URL_SHORTENER`), wyniki SPF/DKIM/DMARC (pass/fail/none) i wersja programu.
- **Ocena programu** (1–5 gwiazdek) i wersja programu.

Dane trafiają do bazy w usłudze Supabase (serwery w UE). Służą wyłącznie do poprawiania wykrywania. Nie zawierają danych osobowych.

**Adres IP:** serwer widzi adres IP połączenia. Zapisujemy tylko jego jednokierunkowy skrót (hash z tajną solą), aby ograniczyć nadużycia (limit liczby zgłoszeń). Skróty są usuwane automatycznie po 2 dniach.

**Sprawdzanie DNS (opcjonalne):** jeśli włączysz sprawdzanie sieciowe, program pyta serwer DNS o rekordy SPF/DMARC domeny nadawcy. Takie zapytanie widzi Twój dostawca DNS, tak jak przy zwykłym przeglądaniu stron.

**Pliki lokalne:** program zapisuje w `%LOCALAPPDATA%\PhishingInspector` tylko datę ostatniej prośby o ocenę. Raporty PDF/HTML zapisuje tylko tam, gdzie wskażesz.

Brak reklam, brak śledzenia, brak kont użytkowników, brak sprzedaży danych.

Kontakt: https://github.com/3en4all/PhishingInspector/issues

## English

Phishing Inspector analyses email messages **locally on your computer**. Message body, subject, sender and recipient addresses, links, attachments and file paths are **never sent anywhere**.

**What may be sent (only when you click it):**
- **Scan feedback** ("correct", "false alarm", "confirmed phishing", "unsure"): verdict, score, codes of the rules that fired (e.g. `URL_SHORTENER`), SPF/DKIM/DMARC results (pass/fail/none) and the app version.
- **App rating** (1–5 stars) and the app version.

The data goes to a Supabase database (EU servers) and is used only to improve detection. It contains no personal data.

**IP address:** the server sees the connection's IP address. Only a one-way salted hash of it is stored, to limit abuse (rate limiting). Hashes are deleted automatically after 2 days.

**DNS checks (optional):** if you enable network checks, the app asks a DNS server for the sender domain's SPF/DMARC records. Your DNS provider sees that query, as with normal browsing.

**Local files:** the app stores only the date of the last rating prompt in `%LOCALAPPDATA%\PhishingInspector`. PDF/HTML reports are saved only where you choose.

No ads, no tracking, no user accounts, no sale of data.

Contact: https://github.com/3en4all/PhishingInspector/issues
