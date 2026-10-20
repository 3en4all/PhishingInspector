import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QLabel

from phishing_inspector.analyzer import analyze_message
from phishing_inspector.gui_app import MainWindow

from corpus import PHISHING


def _visible_texts(window):
    return " ".join(label.text() for label in window.findChildren(QLabel) if label.isVisibleTo(window))


def _case(name):
    return next(case for case in PHISHING if case.name == name)


def test_polish_result_has_no_english_verdict(tmp_path):
    app = QApplication.instance() or QApplication([])
    path = tmp_path / "message.eml"
    path.write_text(_case("bank_display_name_and_link_text").raw, encoding="utf-8")
    analysis = analyze_message(path)
    assert analysis.verdict == "DANGEROUS"

    window = MainWindow("pl")
    window._select_file(path)
    window._on_analysis_finished(analysis)
    app.processEvents()

    content = _visible_texts(window)
    assert window.summary_verdict_label.text() == "NIEBEZPIECZNY"
    assert "DANGEROUS" not in content
    assert window.file_label.text() == "message.eml"
    assert window.export_pdf_button.isEnabled()
    window.close()


def test_feedback_bar_starts_collapsed_and_expands():
    app = QApplication.instance() or QApplication([])
    window = MainWindow("pl")
    window.show()
    app.processEvents()
    assert not window.feedback_body.isVisible()
    window.feedback_toggle.setChecked(True)
    assert window.feedback_body.isVisible()
    window.close()


def test_branding_is_consistent():
    app = QApplication.instance() or QApplication([])  # noqa: F841
    for language in ("pl", "en"):
        window = MainWindow(language)
        content = _visible_texts(window) + window.branding_label.text()
        assert "TechM8" not in content
        assert "3EN4ALL" in content
        window.close()
