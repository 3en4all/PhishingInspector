# Phishing Inspector

**Standalone Windows tool for inspecting suspicious emails, URLs and related content.**

Phishing Inspector is a desktop application designed to support practical analysis of suspicious messages, links and related content in a single local workflow.

The current public release is **v0.2.0-beta** for **Windows x64**.

> Beta software: features and detection logic may still change before the stable release.

## Download

**Latest release:** [Phishing Inspector v0.2.0-beta](https://github.com/3en4all/PhishingInspector/releases/tag/v0.2.0-beta)

### Windows x64 — English

[PhishingInspector-0.2.0-beta-EN-windows-x64.zip](https://github.com/3en4all/PhishingInspector/releases/download/v0.2.0-beta/PhishingInspector-0.2.0-beta-EN-windows-x64.zip)

### Windows x64 — Polish

[PhishingInspector-0.2.0-beta-windows-x64.zip](https://github.com/3en4all/PhishingInspector/releases/download/v0.2.0-beta/PhishingInspector-0.2.0-beta-windows-x64.zip)

No separate Python installation is required.

## What it is

Phishing Inspector is intended as a lightweight desktop utility for structured inspection of potentially suspicious email, URL and file-related content.

Instead of requiring a separate Python environment, the Windows build bundles the runtime and application dependencies needed to launch the tool directly.

## Standalone Windows build

The packaged application includes components required for the desktop build, including:

- Python runtime
- PySide6 / Qt graphical interface libraries
- email and HTML parsing components
- PDF report generation components
- archive and file-format handling libraries
- networking and security-related dependencies

Because these components are bundled with the application, the current package is approximately **76 MB**.

## Current status

**Version:** `v0.2.0-beta`  
**Platform:** Windows x64  
**Languages:** English and Polish  
**Release stage:** Public beta  
**Separate Python installation:** Not required

The beta is intended for testing and feedback. Some functionality, detection logic and interface elements may change before the stable release.

## Project page

More information about the project is available here:

**https://3en4all.github.io/software/phishing-inspector/**

## Releases

All public builds are published in GitHub Releases:

**https://github.com/3en4all/PhishingInspector/releases**

## Feedback

Feedback and bug reports are welcome. If you encounter a problem, please include the application version and a short description of what happened.

## Microsoft Store

A Microsoft Store (MSIX) package is in preparation. Build it with `packaging\msix\build_msix.ps1`; see `packaging/msix/STORE_LISTING.md`.

## Privacy

Emails are analysed locally. Only optional, user-initiated feedback (verdict, score, rule codes) is sent, with no message content or addresses. See [PRIVACY.md](PRIVACY.md).

## License

The Phishing Inspector core is released under the [MIT License](LICENSE). Future Pro features are distributed separately and are not covered by this license.

## About

Phishing Inspector is part of the broader **3EN4ALL** ecosystem — projects focused on IT infrastructure, Python automation, security tooling and local AI workflows.

**3EN4ALL:** https://3en4all.github.io/
