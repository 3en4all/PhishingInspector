# Microsoft Store — szkic wpisu i kroki / listing draft and steps

## Kroki (kto co robi)

1. **Jack:** załóż darmowe konto deweloperskie (osoba prywatna) w Partner Center: https://storedeveloper.microsoft.com
2. **Jack:** w Partner Center „Nowy produkt → Aplikacja MSIX lub PWA” i zarezerwuj nazwę **Phishing Inspector**.
3. **Jack/Claude:** z „Zarządzanie produktem → Tożsamość produktu” przepisz trzy wartości: `Package/Identity/Name`, `Package/Identity/Publisher` (CN=...), `Package/Properties/PublisherDisplayName`.
4. **Claude:** buduje paczkę z prawdziwą tożsamością:
   `packaging\msix\build_msix.ps1 -IdentityName <Name> -Publisher "<CN=...>" -PublisherDisplayName "<nazwa>"`
5. **Jack:** wgrywa `dist\PhishingInspector-<wersja>-x64.msix`, wkleja teksty poniżej, dodaje zrzuty ekranu i wysyła do certyfikacji. **Publikacja publiczna tylko za zgodą Jacka.**

Ustawienia zgłoszenia: cena **darmowa**; kategoria **Narzędzia deweloperskie → Bezpieczeństwo** (lub „Bezpieczeństwo”); wiek **3+** (IARC: brak treści dla dorosłych); rynki: wszystkie; polityka prywatności: URL do `PRIVACY.md` (np. https://github.com/3en4all/PhishingInspector/blob/main/PRIVACY.md).
Uwaga dla certyfikacji (Notes for certification): „Desktop app (PyInstaller) using runFullTrust. No login needed. Open samples\suspicious.eml from the repository to test analysis. Network use: optional user-initiated anonymous feedback and optional DNS checks.”

## Polski (pl-PL)

**Nazwa:** Phishing Inspector

**Krótki opis (do 100 znaków):**
Sprawdź podejrzanego maila zanim klikniesz. Analiza lokalna, bez wysyłania treści.

**Opis:**
Phishing Inspector sprawdza podejrzane wiadomości e-mail i mówi prostym językiem, czy wyglądają na phishing i dlaczego.

Przeciągnij plik .eml lub .msg (zapisany z Outlooka, Thunderbirda, Gmaila) do okna programu. W kilka sekund dostajesz werdykt: BEZPIECZNY, WYMAGA OSTROŻNOŚCI lub NIEBEZPIECZNY, z listą powodów.

Co sprawdza:
• linki: podszywanie się pod znane marki, literówki w domenach, skracacze, adresy IP, ukryte przekierowania
• nadawcę: SPF, DKIM, DMARC, zgodność domen, podszywanie się pod nazwę wyświetlaną
• załączniki: niebezpieczne typy, podwójne rozszerzenia, makra, archiwa z hasłem
• treść: presja czasu, prośby o dane logowania i płatności

Prywatność: cała analiza odbywa się na Twoim komputerze. Treść maila, adresy, linki i załączniki nigdy nie opuszczają komputera. Raport możesz zapisać jako PDF lub HTML.

Dla kogo: dla każdego, kto dostał dziwnego maila, oraz dla małych firm, biur rachunkowych i serwisów IT, które chcą szybko sprawdzić zgłoszoną wiadomość.

**Funkcje (lista w Store):**
- Werdykt i wyjaśnienie prostym językiem
- Analiza linków, nadawcy, załączników i treści
- Obsługa plików .eml i .msg
- Raport PDF i HTML
- Działa offline, bez konta
- Polski i angielski interfejs

**Słowa kluczowe:** phishing, e-mail, bezpieczeństwo, oszustwo, spam, Outlook, SPF, DKIM

## English (en-US)

**Name:** Phishing Inspector

**Short description:**
Check a suspicious email before you click. Local analysis, nothing uploaded.

**Description:**
Phishing Inspector checks suspicious emails and tells you in plain language whether they look like phishing, and why.

Drag an .eml or .msg file (saved from Outlook, Thunderbird or Gmail) into the window. In seconds you get a verdict: SAFE, SUSPICIOUS or DANGEROUS, with the reasons listed.

What it checks:
• links: brand impersonation, look-alike domains, URL shorteners, raw IP addresses, hidden redirects
• sender: SPF, DKIM, DMARC, domain alignment, display-name spoofing
• attachments: dangerous file types, double extensions, macros, password-protected archives
• content: urgency, requests for credentials and payments

Privacy: all analysis runs on your computer. Message content, addresses, links and attachments never leave it. Save the report as PDF or HTML.

Who it is for: anyone who received a strange email, and small businesses, accounting offices and IT service providers who need to check a reported message quickly.

**Features:**
- Verdict with a plain-language explanation
- Link, sender, attachment and content analysis
- .eml and .msg files
- PDF and HTML report
- Works offline, no account
- English and Polish interface

**Keywords:** phishing, email, security, scam, spam, Outlook, SPF, DKIM

## Zrzuty ekranu / Screenshots (1366×768 lub 1920×1080, PNG)

Po 4 dla PL i EN (interfejs w danym języku):
1. Okno główne z przeciągniętym plikiem i werdyktem NIEBEZPIECZNY (np. `samples\suspicious.eml`).
2. Lista powodów z wyjaśnieniami (zakładka ustaleń).
3. Analiza linków (podszywanie się pod markę).
4. Raport PDF otwarty obok programu.

Grafika: logo 300×300 jest w `packaging\msix\Assets\StoreListing300x300.png` (tymczasowe, do podmiany na finalne).
