"""Renders main-window screenshots (for the Store listing and UI review).

Uses synthetic messages from the test corpus, so no real mail is shown.
Run from the repository root:

    python tools/store_screenshots.py [output_dir] [--lang pl|en]

On a machine without a display set QT_QPA_PLATFORM=offscreen.
"""
from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from PySide6.QtWidgets import QApplication  # noqa: E402

import corpus  # noqa: E402
from phishing_inspector.analyzer import analyze_message  # noqa: E402
from phishing_inspector.gui_app import MainWindow  # noqa: E402
from phishing_inspector.gui_theme import apply_app_look  # noqa: E402

CASES = {
    "safe": ("bank_real_statement", "wyciag-bankowy-pazdziernik.eml"),
    "dangerous": ("bank_display_name_and_link_text", "pilne-blokada-konta.eml"),
}
SIZES = ((1920, 1080), (1366, 768))


def _case(name: str):
    for case in (*corpus.PHISHING, *corpus.LEGITIMATE):
        if case.name == name:
            return case
    raise KeyError(name)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", nargs="?", default="screenshots")
    parser.add_argument("--lang", default="pl", choices=("pl", "en"))
    args = parser.parse_args()

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    app = QApplication.instance() or QApplication(sys.argv)
    apply_app_look(app)

    with tempfile.TemporaryDirectory() as tmp:
        for label, (case_name, filename) in CASES.items():
            path = Path(tmp) / filename
            path.write_text(_case(case_name).raw, encoding="utf-8")
            analysis = analyze_message(path)

            for width, height in SIZES:
                window = MainWindow(args.lang)
                window.resize(width, height)
                window.show()
                window._select_file(path)
                window._on_analysis_finished(analysis)
                app.processEvents()
                target = out / f"{args.lang}-{label}-{width}x{height}.png"
                window.grab().save(str(target))
                print(target)
                window.hide()
                window.deleteLater()
                app.processEvents()

        empty = MainWindow(args.lang)
        empty.resize(*SIZES[0])
        empty.show()
        app.processEvents()
        target = out / f"{args.lang}-start-{SIZES[0][0]}x{SIZES[0][1]}.png"
        empty.grab().save(str(target))
        print(target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
