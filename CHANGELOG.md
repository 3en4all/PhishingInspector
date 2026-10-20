# Changelog

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
