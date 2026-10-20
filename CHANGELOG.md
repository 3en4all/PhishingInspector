# Changelog

## 0.3.1-beta (unreleased)

App
- New dark interface ("security dashboard"): compact drop zone with the chosen file shown as a chip, strong result card (verdict, risk score, risk bar), equal tiles for SPF/DKIM/DMARC/links/attachments/origin IP, a separate card with the explanation and colour-coded key findings, cleaner tabs, collapsible feedback bar. Layout fits 1366×768 and 1920×1080. Analysis logic unchanged.
- One brand everywhere: Phishing Inspector / 3EN4ALL ("Powered by TechM8" removed). The Polish UI no longer shows English statuses (verdict, SPF/DKIM/DMARC, true/false); findings lead with the Polish explanation.
- `tools/store_screenshots.py` renders Store/review screenshots from synthetic messages (PL/EN, 1920×1080 and 1366×768).
- Help → About window (PL/EN with the app language, version read from the package). Links open only on click; links to GitHub, privacy policy, website, Facebook, YouTube and buycoffee.to; a link without a confirmed address (ecosystem page) stays hidden until filled in `about_dialog.py`.

Licence and distribution
- MIT licence for the core (LICENSE); Pro features will live in a separate repository.
- Privacy policy (PRIVACY.md, PL + EN).
- Microsoft Store packaging: `packaging/msix/` (one-folder build with a single exe that picks PL/EN from the Windows language, AppxManifest template, icons, `build_msix.ps1`, one-click `zbuduj_msix.cmd`) and a Store listing draft.

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
