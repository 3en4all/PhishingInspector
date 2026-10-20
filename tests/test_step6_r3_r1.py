from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from phishing_inspector.gui_app import MainWindow
from phishing_inspector.url_analysis import analyze_url


class Step6R3R1Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def test_google_account_url_is_not_suspicious(self) -> None:
        result = analyze_url(
            "https://accounts.google.com/account/permissions"
        )

        self.assertFalse(result.suspicious)

    def test_fake_google_url_is_suspicious(self) -> None:
        result = analyze_url(
            "https://google.com.secure-login.example/account"
        )

        self.assertTrue(result.suspicious)

    def test_main_window_accepts_drops(self) -> None:
        window = MainWindow()

        self.assertTrue(window.acceptDrops())
        self.assertTrue(window.drop_area.acceptDrops())

        window.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
