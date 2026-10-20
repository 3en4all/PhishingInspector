import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QLabel

from phishing_inspector import __version__
from phishing_inspector.about_dialog import AboutDialog
from phishing_inspector.gui_app import MainWindow


def _texts(dialog):
    return " ".join(label.text() for label in dialog.findChildren(QLabel))


def test_about_dialog_follows_language_and_shows_version():
    app = QApplication.instance() or QApplication([])
    for language, title in (("pl", "O programie"), ("en", "About")):
        dialog = AboutDialog(language=language)
        content = _texts(dialog)
        assert title in dialog.windowTitle()
        assert f"v{__version__}" in content
        assert "github.com/3en4all/PhishingInspector" in content
        assert "PRIVACY.md" in content
        dialog.deleteLater()
    app.processEvents()


def test_unconfirmed_links_are_hidden():
    QApplication.instance() or QApplication([])
    content = _texts(AboutDialog(language="pl"))
    assert "Ekosystem" not in content
    assert "facebook.com/profile.php?id=61588740009580" in content
    assert "youtube.com/@BlastArbiter" in content


def test_help_menu_has_about_action():
    QApplication.instance() or QApplication([])
    window = MainWindow("en")
    menus = [action.text() for action in window.menuBar().actions()]
    assert "Help" in menus
    assert window.about_action.text() == "About"
    window.close()
