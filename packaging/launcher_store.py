"""Entry point for the Microsoft Store (MSIX) build: one executable for both languages.

The language follows the Windows display language (Polish -> PL, anything else -> EN).
`--lang pl` or `--lang en` overrides it.
"""

import sys

from phishing_inspector.gui_app import main

LANG_POLISH = 0x15  # primary language id of pl-PL in a Windows LANGID


def _language(argv: list[str]) -> str:
    for i, arg in enumerate(argv):
        if arg.startswith("--lang="):
            return "en" if arg.split("=", 1)[1].lower().startswith("en") else "pl"
        if arg == "--lang" and i + 1 < len(argv):
            return "en" if argv[i + 1].lower().startswith("en") else "pl"
    try:
        import ctypes

        langid = ctypes.windll.kernel32.GetUserDefaultUILanguage()
        return "pl" if (langid & 0x3FF) == LANG_POLISH else "en"
    except Exception:
        return "pl"


if __name__ == "__main__":
    raise SystemExit(main(_language(sys.argv[1:])))
