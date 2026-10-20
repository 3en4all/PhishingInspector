# Changelog

## 0.3.1-beta (unreleased)

Detection (measured on a new synthetic corpus, `tests/corpus_more.py`: 0.3.0 marked 9 of 14 typical phishing emails SAFE and raised 2 false alarms; now 20 of 20 phishing flagged, 24 of 24 legitimate SAFE)
- Brand in a subdomain of someone else's domain scores on its own (`mbank.pl.secure-login.top`, `olx.platnosc24.pl`), URL_BRAND_SUBDOMAIN.
- Links to a public IP address score on their own (URL_IP_HOST); local network addresses do not.
- Disguised brand names in the sender name: "PayPaI", "Allegr0", Cyrillic letters, invisible characters.
- Login pages hidden in CMS folders of hacked sites (`/wp-content/.../login.php`), URL_HACKED_SITE_PATH.
- Reply-To pointing to a different free mailbox (CEO/invoice fraud), SENDER_REPLY_TO_FREEMAIL.
- Brand in the subject when neither the sender nor the links belong to it and the text asks for login details, CONTENT_BRAND_MISMATCH.
- QR-code phishing (CONTENT_QR_LURE) and transfer-to-new-account phrases.

False alarms fixed
- "Ing. Petr Novak" is no longer ING Bank: aliases of three letters or fewer match only in capitals.
- PKO group companies (PKO Leasing, PKO TFI, ...) are no longer PKO impersonation.

## 0.3.0-beta

Detection
- Authentication-Results are trusted only from the receiving server (first header's authserv-id); forged "pass" results added by the sender are ignored and scored (AUTH_FORGED_RESULTS).
- Brand impersonation: display name vs. sender domain, lookalike/combosquatting domains (homoglyphs, digit swaps, IDN), brand names on foreign domains; ~35 global and Polish brands.
- Links: HTML href vs. visible text mismatch, risky TLDs, brand imitation in URLs, redirects to suspicious targets, javascript:/data: links, form actions, links inside PDF/HTML attachments.
- Attachments: HTML/SVG, disk images, encrypted archives, executables detected by content, active PDFs.
- Content lures (urgency, payment, credentials, threats) in Polish and English.
- Every score point now has a stable rule code and appears in the score breakdown.
- Registrable domains use the Public Suffix List (offline snapshot from tldextract).

Privacy
- DNS lookups of the sender domain are off by default (GUI checkbox / `--network-checks`).
- Feedback sends only rule codes and SPF/DKIM/DMARC results, never addresses, URLs or file names.

App
- One GUI codebase for Polish and English; analysis runs in a background thread.
- .msg: transport headers and HTML body are read; limitations are shown when headers are missing.
- Reports include rule codes, score breakdown and analysis limitations; explanations follow the GUI language.
- Build: `packaging/build.ps1` + `packaging/phishing_inspector.spec` (relative paths, builds PL and EN, SHA256SUMS).
