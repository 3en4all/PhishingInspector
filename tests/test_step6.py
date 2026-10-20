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


class GuiSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def test_main_window_constructs(self) -> None:
        window = MainWindow()

        self.assertEqual(window.windowTitle(), "Phishing Inspector")
        self.assertFalse(window.analyze_button.isEnabled())
        self.assertFalse(window.export_pdf_button.isEnabled())
        self.assertFalse(window.export_html_button.isEnabled())

        window.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
