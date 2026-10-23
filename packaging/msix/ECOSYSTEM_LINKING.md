# 3EN4ALL cross-project linking policy

Goal: connect PhishingInspector, website, educational channels and optional community support without ads, pressure, tracking, or intrusive prompts.

## One hub
Use https://3en4all.github.io/ as the canonical link hub. The app's product-specific landing page is https://3en4all.github.io/software/phishing-inspector/. Avoid stuffing all social URLs in each surface.

## PhishingInspector
- Main interface: keep task-focused, no donation or social banners, no popups.
- About / O programie: creator 3en4All, current app version, project page, source and issue tracker, privacy policy.
- Footer, if any: only "Created by 3en4All" with one link to project page.
- Voluntary support link appears only in About or on the website; never during scanning, error handling or safety warnings.
- No analytics/tracking additions or outbound requests without separate privacy review and explicit user action.

## Microsoft Store
- First describe what the app does, its limitations, offline/local handling and supported formats.
- Place the creator/project URL and support URL toward the end of the listing.
- Follow Store link and solicitation policies; if third-party funding links are disallowed in listing metadata, keep them on the project website instead.
- Free = 0 PLN. No promises of Pro capabilities before release.

## Video & social publishing (PL/EN)
- Educational content first. Add one modest link to 3EN4ALL when relevant; route app-specific security videos to the PhishingInspector landing page.
- Cross-link videos, website and software only when the subject is relevant, rather than repeating the full social directory everywhere.
- Platform-specific descriptions and language. No automated cross-posting before explicit user authorization.
- API-only interactions for connected platforms; do not use browser accounts without separate approval.

## Canonical URLs already recorded
- Hub: https://3en4all.github.io/
- PhishingInspector: https://3en4all.github.io/software/phishing-inspector/
- GitHub: https://github.com/3en4all/PhishingInspector
- Facebook: https://www.facebook.com/profile.php?id=61588740009580

## Pending confirmation
- Exact YouTube PL/EN channels and which to feature.
- Instagram, Threads and TikTok profile URLs and whether each profile is live.
- Exact Buy Me a Coffee URL (do not infer or fabricate).

## Example microcopy
PL: "PhishingInspector jest bezpłatnym projektem 3EN4ALL. Więcej o aplikacji i innych projektach: 3en4all.github.io."
EN: "PhishingInspector is a free project by 3EN4ALL. Learn more about the app and related projects at 3en4all.github.io."

Not a claim that these elements are implemented in the shipped binary. Implement the in-app About UI separately and rebuild before submitting an updated MSIX.
