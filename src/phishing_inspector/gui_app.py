from __future__ import annotations

import html
import os
import sys
import threading
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QObject, QSize, Qt, QThread, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QIcon
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QCheckBox,
    QDialog,
    QFileDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from .about_dialog import AboutDialog
from .analyzer import analyze_message
from .i18n import explain_finding, friendly_auth_value, normalize_language, text
from .html_report import write_html_report
from .pdf_report import write_pdf_report
from .report_model import build_report_model
from .feedback_store import (
    mark_app_rating_prompted,
    should_prompt_for_app_rating,
    submit_app_rating_cloud,
    submit_scan_feedback_cloud,
)
from . import __version__
from .runtime_paths import asset_path


SUPPORTED_EXTENSIONS = {".eml", ".msg"}


def extract_supported_drop_path(event) -> Path | None:
    mime = event.mimeData()

    if not mime.hasUrls():
        return None

    for url in mime.urls():
        if not url.isLocalFile():
            continue

        local_file = url.toLocalFile()

        if not local_file:
            continue

        path = Path(local_file)

        if path.is_file() and path.suffix.lower() in SUPPORTED_EXTENSIONS:
            return path.resolve()

    return None



def _friendly_auth_value(field: str, value, language: str = "pl") -> str:
    return friendly_auth_value(language, field, value)


def _build_human_summary(analysis, language: str = "pl") -> tuple[str, list[str]]:
    t = lambda key, **values: text(language, key, **values)  # noqa: E731

    verdict = analysis.verdict
    attachments = analysis.attachments
    urls = analysis.urls
    auth = analysis.authentication or {}
    findings = analysis.reasons or []

    suspicious_urls = sum(1 for item in urls if item.suspicious)
    suspicious_attachments = sum(1 for item in attachments if item.suspicious)

    auth_results = [
        auth.get("spf"),
        auth.get("dkim"),
        auth.get("dmarc"),
    ]
    auth_pass_count = sum(1 for value in auth_results if value == "pass")

    if verdict == "SAFE":
        intro = t("summary_safe")
    elif verdict == "SUSPICIOUS":
        intro = t("summary_suspicious")
    else:
        intro = t("summary_dangerous")

    bullets: list[str] = []

    scored = [f for f in getattr(analysis, "findings", []) if f.points > 0]
    if scored and verdict != "SAFE":
        top = max(scored, key=lambda f: f.points)
        bullets.append(t("bullet_top", reason=top.message))

    bullets.append(t("bullet_auth", count=auth_pass_count))

    if urls:
        bullets.append(t("bullet_links", total=len(urls), suspicious=suspicious_urls))
    else:
        bullets.append(t("bullet_no_links"))

    if attachments:
        archive_exts = {".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".iso", ".img", ".vhd", ".vhdx", ".cab"}
        archive_count = sum(
            1
            for item in attachments
            if Path(item.filename).suffix.lower() in archive_exts
        )

        bullets.append(
            t("bullet_attachments", total=len(attachments), suspicious=suspicious_attachments)
        )

        if archive_count:
            bullets.append(t("bullet_archives", count=archive_count))

        bullets.append(t("bullet_attachment_warning"))
    else:
        bullets.append(t("bullet_no_attachments"))

    if findings:
        bullets.append(t("bullet_findings", count=len(findings)))

    for note in getattr(analysis, "limitations", []) or []:
        bullets.append(f"{t('limitations')} {note}")

    return intro, bullets

class DropArea(QLabel):
    def __init__(self, on_file_dropped, label: str = "Drop .eml or .msg file here") -> None:
        super().__init__(label)
        self._on_file_dropped = on_file_dropped

        self.setAlignment(Qt.AlignCenter)
        self.setAcceptDrops(True)
        self.setMinimumHeight(120)
        self.setStyleSheet(
            "QLabel {"
            "border: 2px dashed #777;"
            "border-radius: 8px;"
            "padding: 24px;"
            "font-size: 16px;"
            "}"
        )

    def dragEnterEvent(self, event) -> None:
        path = extract_supported_drop_path(event)

        if path is not None:
            event.setDropAction(Qt.CopyAction)
            event.accept()
        else:
            event.ignore()

    def dragMoveEvent(self, event) -> None:
        path = extract_supported_drop_path(event)

        if path is not None:
            event.setDropAction(Qt.CopyAction)
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event) -> None:
        path = extract_supported_drop_path(event)

        if path is None:
            event.ignore()
            return

        self._on_file_dropped(path)
        event.setDropAction(Qt.CopyAction)
        event.accept()



class AppRatingDialog(QDialog):
    def __init__(self, parent=None, language: str = "pl") -> None:
        super().__init__(parent)
        t = lambda key: text(language, key)  # noqa: E731
        self.setWindowTitle(t("rating_title"))
        self.setModal(True)
        self.setMinimumWidth(420)

        layout = QVBoxLayout(self)

        title = QLabel(t("rating_question"))
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 17px; font-weight: 700;")
        layout.addWidget(title)

        info = QLabel(t("rating_info"))
        info.setWordWrap(True)
        info.setAlignment(Qt.AlignCenter)
        layout.addWidget(info)

        roadmap = QLabel(t("rating_roadmap"))
        roadmap.setWordWrap(True)
        roadmap.setAlignment(Qt.AlignCenter)
        roadmap.setStyleSheet(
            "QLabel { color: #b9c0c8; margin: 8px 10px 2px 10px; }"
        )
        layout.addWidget(roadmap)

        stars = QHBoxLayout()
        stars.addStretch(1)
        self._star_buttons = []

        for rating in range(1, 6):
            button = QPushButton("☆")
            button.setFlat(True)
            button.setFixedSize(52, 52)
            button.setStyleSheet(
                "QPushButton { font-size: 34px; border: none; color: #d6a800; }"
                "QPushButton:hover { color: #ffc107; "
                "background: rgba(255,193,7,0.08); border-radius: 8px; }"
            )
            button.setToolTip(f"{rating}/5")
            button.clicked.connect(
                lambda _checked=False, value=rating: self._choose_rating(value)
            )
            self._star_buttons.append(button)
            stars.addWidget(button)

        stars.addStretch(1)
        layout.addLayout(stars)

        skip = QPushButton(t("not_now"))
        skip.clicked.connect(self.reject)
        layout.addWidget(skip)

    def _choose_rating(self, rating: int) -> None:
        for index, button in enumerate(self._star_buttons, start=1):
            button.setText("★" if index <= rating else "☆")

        threading.Thread(
            target=submit_app_rating_cloud,
            kwargs={"rating": rating, "app_version": __version__},
            daemon=True,
        ).start()
        self.accept()


class _AnalysisWorker(QObject):
    """Runs analyze_message() off the GUI thread so the window stays responsive."""

    finished = Signal(object)
    failed = Signal(str)

    def __init__(self, path: Path, network_checks: bool) -> None:
        super().__init__()
        self._path = path
        self._network_checks = network_checks

    def run(self) -> None:
        try:
            result = analyze_message(self._path, network_checks=self._network_checks)
        except Exception as exc:  # shown to the user in a message box
            self.failed.emit(f"{type(exc).__name__}: {exc}")
            return
        self.finished.emit(result)


class MainWindow(QMainWindow):
    def __init__(self, language: str | None = None) -> None:
        super().__init__()

        self.language = normalize_language(
            language or os.environ.get("PHISHING_INSPECTOR_LANG")
        )
        self._analysis_thread: QThread | None = None
        self._analysis_worker: _AnalysisWorker | None = None

        self.setWindowTitle("Phishing Inspector")
        self.resize(1180, 760)
        self.setAcceptDrops(True)

        self._selected_file: Path | None = None
        self._analysis = None
        self._technical_log_entries: list[tuple[str, str, str]] = []
        self._technical_log_level = "Detailed"
        self._technical_log_visible = False
        self._theme_name = "Emerald"

        root = QWidget()
        self.setCentralWidget(root)

        layout = QVBoxLayout(root)

        theme_row = QHBoxLayout()
        theme_row.addStretch(1)

        self.theme_buttons = {}
        for theme_name, theme_color in (
            ("Emerald", "#2e7d32"),
            ("Tech Blue", "#1565c0"),
            ("Amber", "#ef6c00"),
        ):
            button = QPushButton(theme_name)
            button.setCheckable(True)
            button.setMinimumHeight(26)
            button.setMaximumHeight(28)
            button.setStyleSheet(
                "QPushButton {"
                f"background: {theme_color}; color: white; "
                "font-size: 11px; font-weight: 700; "
                "border-radius: 6px; padding: 3px 9px;"
                "}"
                "QPushButton:checked { border: 2px solid white; }"
            )
            button.clicked.connect(
                lambda _checked=False, name=theme_name: self._apply_theme(name)
            )
            self.theme_buttons[theme_name] = button
            theme_row.addWidget(button)

        layout.addLayout(theme_row)

        self.drop_area = DropArea(self._select_file, self._t("drop_here"))
        layout.addWidget(self.drop_area)

        controls = QHBoxLayout()

        self.analyze_button = QPushButton(self._t("analyze"))
        self.analyze_button.clicked.connect(self._run_analysis)
        self.analyze_button.setEnabled(False)
        self.analyze_button.setMinimumSize(160, 44)
        self.analyze_button.setMaximumHeight(46)
        controls.addWidget(self.analyze_button)

        self.open_button = QPushButton(self._t("open_file"))
        self.open_button.clicked.connect(self._open_file_dialog)
        self.open_button.setMinimumSize(120, 40)
        self.open_button.setMaximumHeight(42)
        self.open_button.setStyleSheet(
            "QPushButton { background: #f9a825; color: #1a1a1a; "
            "font-size: 13px; font-weight: 700; border: 1px solid #d18b00; "
            "border-radius: 8px; padding: 6px 14px; }"
            "QPushButton:hover { background: #ffb300; }"
            "QPushButton:pressed { background: #e69800; }"
        )
        controls.addWidget(self.open_button)

        self.technical_log_button = QPushButton(self._t("technical_log"))
        self.technical_log_button.setCheckable(True)
        self.technical_log_button.setMinimumSize(118, 38)
        self.technical_log_button.setMaximumHeight(40)
        self.technical_log_button.setStyleSheet(
            "QPushButton { background: #37474f; color: #e8eef2; "
            "font-size: 12px; font-weight: 700; border: 1px solid #607d8b; "
            "border-radius: 7px; padding: 6px 10px; }"
            "QPushButton:hover { background: #455a64; }"
            "QPushButton:checked { background: #263238; border: 2px solid #90a4ae; }"
        )
        self.technical_log_button.clicked.connect(self._toggle_technical_log)
        controls.addWidget(self.technical_log_button)

        self.export_pdf_button = QPushButton(self._t("export_pdf"))
        self.export_pdf_button.clicked.connect(self._export_pdf)
        self.export_pdf_button.setEnabled(False)
        controls.addWidget(self.export_pdf_button)

        self.export_html_button = QPushButton(self._t("export_html"))
        self.export_html_button.clicked.connect(self._export_html)
        self.export_html_button.setEnabled(False)
        controls.addWidget(self.export_html_button)

        self.network_checks_box = QCheckBox(self._t("network_checks"))
        self.network_checks_box.setChecked(False)
        self.network_checks_box.setToolTip(self._t("network_checks_tip"))
        controls.addWidget(self.network_checks_box)

        controls.addStretch(1)
        layout.addLayout(controls)

        result_card = QGroupBox(self._t("result_card"))
        result_layout = QVBoxLayout(result_card)
        result_layout.setContentsMargins(14, 12, 14, 12)
        result_layout.setSpacing(10)

        self.summary_verdict_label = QLabel(self._t("no_analysis"))
        self.summary_verdict_label.setAlignment(Qt.AlignCenter)
        self.summary_verdict_label.setMinimumHeight(54)
        result_layout.addWidget(self.summary_verdict_label)

        meta_row = QHBoxLayout()
        meta_row.setSpacing(8)

        self.score_chip = QLabel("Score: -")
        self.spf_chip = QLabel("SPF: -")
        self.dkim_chip = QLabel("DKIM: -")
        self.dmarc_chip = QLabel("DMARC: -")
        self.urls_chip = QLabel("URLs: -")
        self.attachments_chip = QLabel("Attachments: -")

        for chip in (
            self.score_chip,
            self.spf_chip,
            self.dkim_chip,
            self.dmarc_chip,
            self.urls_chip,
            self.attachments_chip,
        ):
            chip.setAlignment(Qt.AlignCenter)
            chip.setMinimumHeight(28)
            chip.setStyleSheet(
                "QLabel { background: #2a2d30; border: 1px solid #42474c; "
                "border-radius: 7px; padding: 4px 8px; font-weight: 700; }"
            )
            meta_row.addWidget(chip)

        result_layout.addLayout(meta_row)

        details_row = QGridLayout()
        self.file_label = QLabel("-")
        self.verdict_label = QLabel("-")
        self.score_label = QLabel("-")
        self.origin_ip_label = QLabel("-")
        details_row.addWidget(QLabel(self._t("file")), 0, 0)
        details_row.addWidget(self.file_label, 0, 1)
        details_row.addWidget(QLabel(self._t("origin_ip")), 0, 2)
        details_row.addWidget(self.origin_ip_label, 0, 3)
        details_row.addWidget(QLabel(self._t("verdict")), 1, 0)
        details_row.addWidget(self.verdict_label, 1, 1)
        details_row.addWidget(QLabel(self._t("score")), 1, 2)
        details_row.addWidget(self.score_label, 1, 3)
        result_layout.addLayout(details_row)

        what_title = QLabel(self._t("what_it_means"))
        what_title.setStyleSheet("font-size: 13px; font-weight: 800; margin-top: 4px;")
        result_layout.addWidget(what_title)

        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        self.summary_text.setMinimumHeight(120)
        self.summary_text.setMaximumHeight(170)
        result_layout.addWidget(self.summary_text)

        layout.addWidget(result_card)

        self.feedback_group = QGroupBox(self._t("feedback_group"))
        feedback_layout = QHBoxLayout(self.feedback_group)

        self.feedback_buttons = QButtonGroup(self)
        feedback_options = [
            (self._t("feedback_correct"), "correct"),
            (self._t("feedback_false_positive"), "false_positive"),
            (self._t("feedback_phishing"), "confirmed_phishing"),
            (self._t("feedback_unsure"), "unsure"),
        ]

        for label, value in feedback_options:
            button = QRadioButton(label)
            button.setProperty("feedback_value", value)
            self.feedback_buttons.addButton(button)
            feedback_layout.addWidget(button)

        self.feedback_save_button = QPushButton(self._t("feedback_save"))
        self.feedback_save_button.setToolTip(self._t("feedback_tip"))
        self.feedback_save_button.clicked.connect(self._save_feedback)
        self.feedback_save_button.setEnabled(False)
        feedback_layout.addWidget(self.feedback_save_button)

        layout.addWidget(self.feedback_group)
        self.feedback_buttons.buttonClicked.connect(
            lambda _button: self.feedback_save_button.setEnabled(True)
        )

        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)

        self.headers_text = QTextEdit()
        self.headers_text.setReadOnly(True)
        self.tabs.addTab(self.headers_text, self._t("tab_headers"))

        self.auth_table = QTableWidget(0, 2)
        self.auth_table.setHorizontalHeaderLabels([self._t("field"), self._t("value")])
        self.tabs.addTab(self.auth_table, self._t("tab_auth"))

        self.urls_list = QListWidget()
        self.tabs.addTab(self.urls_list, self._t("tab_urls"))

        self.attachments_list = QListWidget()
        self.tabs.addTab(self.attachments_list, self._t("tab_attachments"))

        self.findings_list = QListWidget()
        self.tabs.addTab(self.findings_list, self._t("tab_findings"))

        self.technical_log_panel = QGroupBox(self._t("technical_log"))
        self.technical_log_panel.setMinimumWidth(360)
        self.technical_log_panel.setMaximumWidth(460)
        technical_log_layout = QVBoxLayout(self.technical_log_panel)

        log_controls = QHBoxLayout()
        self.log_normal_button = QPushButton(self._t("log_normal"))
        self.log_detailed_button = QPushButton(self._t("log_detailed"))
        self.log_normal_button.setCheckable(True)
        self.log_detailed_button.setCheckable(True)
        self.log_detailed_button.setChecked(True)

        self.log_normal_button.clicked.connect(
            lambda: self._set_technical_log_level("Normal")
        )
        self.log_detailed_button.clicked.connect(
            lambda: self._set_technical_log_level("Detailed")
        )

        self.copy_log_button = QPushButton(self._t("copy_log"))
        self.copy_log_button.clicked.connect(self._copy_technical_log)

        log_controls.addWidget(self.log_normal_button)
        log_controls.addWidget(self.log_detailed_button)
        log_controls.addStretch(1)
        log_controls.addWidget(self.copy_log_button)
        technical_log_layout.addLayout(log_controls)

        self.technical_log_text = QTextEdit()
        self.technical_log_text.setReadOnly(True)
        self.technical_log_text.setMinimumHeight(220)
        self.technical_log_text.setStyleSheet(
            "QTextEdit {"
            "background: #111417; color: #d8e2e8; "
            "font-family: Consolas, 'Courier New', monospace; "
            "font-size: 12px; border: 1px solid #37474f; "
            "border-radius: 6px; padding: 8px;"
            "}"
        )
        technical_log_layout.addWidget(self.technical_log_text)

        self.technical_log_panel.setVisible(False)

        self.main_content_row = QHBoxLayout()
        self.main_content_row.setSpacing(10)
        self.main_content_row.addWidget(self.tabs, 1)
        self.main_content_row.addWidget(self.technical_log_panel, 0)

        layout.removeWidget(self.tabs)
        layout.addLayout(self.main_content_row, 1)

        self.statusBar().setStyleSheet(
            "QStatusBar { border: none; }"
            "QStatusBar::item { border: none; }"
        )
        self.statusBar().showMessage(self._t("ready"))

        self.branding_label = QLabel(
            '<a href="https://3en4all.github.io/" style="text-decoration:none;">'
            '<span style="font-weight:700;">Powered by TechM8</span></a>'
        )
        self.branding_label.setAlignment(Qt.AlignCenter)
        self.branding_label.setOpenExternalLinks(True)
        self.branding_label.setMinimumWidth(220)

        self.statusBar().addPermanentWidget(self.branding_label, 1)

        self.buycoffee_button = QPushButton()
        self.buycoffee_button.setToolTip(self._t("buycoffee_tip"))
        self.buycoffee_button.setCursor(Qt.PointingHandCursor)
        self.buycoffee_button.setFixedSize(156, 40)
        self.buycoffee_button.setIcon(
            QIcon(str(asset_path(self._t("buycoffee_asset"))))
        )
        self.buycoffee_button.setIconSize(QSize(156, 40))
        self.buycoffee_button.setStyleSheet(
            "QPushButton {"
            "border: none;"
            "padding: 0;"
            "margin: 0 8px 0 0;"
            "background: transparent;"
            "}"
        )
        self.buycoffee_button.clicked.connect(
            lambda: QDesktopServices.openUrl(
                QUrl("https://buycoffee.to/3en4all")
            )
        )
        self.statusBar().addPermanentWidget(self.buycoffee_button, 0)

        help_menu = self.menuBar().addMenu(self._t("menu_help"))
        self.about_action = help_menu.addAction(self._t("menu_about"))
        self.about_action.triggered.connect(self._show_about)

        self._apply_theme("Emerald")

    def _show_about(self) -> None:
        AboutDialog(self, self.language).exec()

    def _t(self, key: str, **values) -> str:
        return text(self.language, key, **values)

    def dragEnterEvent(self, event) -> None:
        path = extract_supported_drop_path(event)

        if path is not None:
            event.setDropAction(Qt.CopyAction)
            event.accept()
        else:
            event.ignore()

    def dragMoveEvent(self, event) -> None:
        path = extract_supported_drop_path(event)

        if path is not None:
            event.setDropAction(Qt.CopyAction)
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event) -> None:
        path = extract_supported_drop_path(event)

        if path is None:
            event.ignore()
            return

        self._select_file(path)
        event.setDropAction(Qt.CopyAction)
        event.accept()

    def _apply_theme(self, theme_name: str) -> None:
        themes = {
            "Emerald": {"primary": "#2e7d32", "hover": "#388e3c", "pressed": "#1b5e20"},
            "Tech Blue": {"primary": "#1565c0", "hover": "#1976d2", "pressed": "#0d47a1"},
            "Amber": {"primary": "#ef6c00", "hover": "#f57c00", "pressed": "#e65100"},
        }
        theme = themes.get(theme_name, themes["Emerald"])
        self._theme_name = theme_name

        for name, button in self.theme_buttons.items():
            button.setChecked(name == theme_name)

        self.analyze_button.setStyleSheet(
            "QPushButton {"
            f"background: {theme['primary']}; color: white; "
            "font-size: 16px; font-weight: 800; border: none; "
            "border-radius: 9px; padding: 10px 24px;"
            "}"
            f"QPushButton:hover {{ background: {theme['hover']}; }}"
            f"QPushButton:pressed {{ background: {theme['pressed']}; }}"
            "QPushButton:disabled { background: #546e5a; color: #cfd8d3; }"
        )

    def _toggle_technical_log(self) -> None:
        self._technical_log_visible = not self._technical_log_visible
        self.technical_log_panel.setVisible(self._technical_log_visible)
        self.technical_log_button.setChecked(self._technical_log_visible)

    def _set_technical_log_level(self, level: str) -> None:
        self._technical_log_level = level
        self.log_normal_button.setChecked(level == "Normal")
        self.log_detailed_button.setChecked(level == "Detailed")
        self._render_technical_log()

    def _copy_technical_log(self) -> None:
        QApplication.clipboard().setText(self.technical_log_text.toPlainText())
        self.statusBar().showMessage(self._t("log_copied"))

    def _clear_technical_log(self) -> None:
        self._technical_log_entries.clear()
        if hasattr(self, "technical_log_text"):
            self.technical_log_text.clear()

    def _log_event(self, category: str, message: str, level: str = "normal") -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        self._technical_log_entries.append(
            (level, category, f"{timestamp} [{category}] {message}")
        )
        self._render_technical_log()

    def _render_technical_log(self) -> None:
        if not hasattr(self, "technical_log_text"):
            return
        detailed = self._technical_log_level == "Detailed"
        lines = [
            line
            for level, _category, line in self._technical_log_entries
            if detailed or level == "normal"
        ]
        self.technical_log_text.setPlainText("\n".join(lines))

    def _build_analysis_technical_log(self) -> None:
        analysis = self._analysis
        if analysis is None:
            return

        auth = analysis.authentication or {}
        alignment = auth.get("alignment", {}) or {}

        self._log_event("PARSE", "Message structure parsed successfully.", "normal")
        self._log_event(
            "HEADER",
            f"Received headers: {len(analysis.headers.received_headers)}",
            "detailed",
        )
        self._log_event(
            "HEADER",
            f"Originating IP: {analysis.received_chain.get('originating_ip') or 'not determined'}",
            "detailed",
        )
        self._log_event("AUTH", f"SPF = {auth.get('spf', 'unknown')}", "normal")
        self._log_event("AUTH", f"DKIM = {auth.get('dkim', 'unknown')}", "normal")
        self._log_event("AUTH", f"DMARC = {auth.get('dmarc', 'unknown')}", "normal")
        self._log_event(
            "AUTH",
            f"DKIM domain = {auth.get('dkim_domain') or 'none'}",
            "detailed",
        )
        self._log_event(
            "AUTH",
            f"SPF aligned = {alignment.get('spf_aligned')}",
            "detailed",
        )
        self._log_event(
            "AUTH",
            f"DKIM aligned = {alignment.get('dkim_aligned')}",
            "detailed",
        )
        self._log_event(
            "AUTH",
            f"Authentication-Results server = {auth.get('authserv_id') or '-'}, "
            f"verified = {auth.get('verified')}, "
            f"ignored headers = {len(auth.get('ignored_headers') or [])}",
            "detailed",
        )

        suspicious_urls = [item for item in analysis.urls if item.suspicious]
        self._log_event(
            "URL",
            f"URLs extracted: {len(analysis.urls)}; suspicious: {len(suspicious_urls)}",
            "normal",
        )
        for index, item in enumerate(analysis.urls, start=1):
            self._log_event(
                "URL",
                f"URL #{index}: host={item.hostname or 'unknown'}, "
                f"source={item.source}, text={item.link_text or '-'}, "
                f"rules={','.join(item.rule_codes) or '-'}, "
                f"suspicious={item.suspicious}, "
                f"reasons={'; '.join(item.reasons) if item.reasons else 'none'}",
                "detailed",
            )

        suspicious_attachments = [item for item in analysis.attachments if item.suspicious]
        self._log_event(
            "ATTACHMENT",
            f"Attachments: {len(analysis.attachments)}; "
            f"suspicious: {len(suspicious_attachments)}",
            "normal",
        )
        for index, item in enumerate(analysis.attachments, start=1):
            self._log_event(
                "ATTACHMENT",
                f"Attachment #{index}: filename={item.filename}, "
                f"type={item.content_type}, size={item.size}, "
                f"rules={','.join(item.rule_codes) or '-'}, "
                f"suspicious={item.suspicious}, "
                f"reasons={'; '.join(item.reasons) if item.reasons else 'none'}",
                "detailed",
            )

        for finding in getattr(analysis, "findings", []):
            self._log_event("RULE", f"{finding.code} +{finding.points}", "detailed")

        for reason in analysis.reasons:
            self._log_event("FINDING", reason, "detailed")

        self._log_event("SCORE", f"Deterministic score = {analysis.score}/100", "normal")
        self._log_event("RESULT", f"Verdict = {analysis.verdict}", "normal")
        self._log_event("PRIVACY", self._t("log_privacy_end"), "normal")

    def _open_file_dialog(self) -> None:
        filename, _ = QFileDialog.getOpenFileName(
            self,
            self._t("select_email"),
            "",
            self._t("email_files"),
        )

        if filename:
            self._select_file(Path(filename))

    def _select_file(self, path: Path) -> None:
        resolved = path.resolve()

        if not resolved.is_file():
            QMessageBox.warning(self, self._t("invalid_file"), self._t("not_a_file"))
            return

        if resolved.suffix.lower() not in SUPPORTED_EXTENSIONS:
            QMessageBox.warning(
                self,
                self._t("unsupported_file"),
                self._t("only_eml_msg"),
            )
            return

        self._selected_file = resolved
        self.file_label.setText(str(self._selected_file))
        self.drop_area.setText(str(self._selected_file))
        self.analyze_button.setEnabled(True)
        self.statusBar().showMessage(self._t("file_selected"))

    def _run_analysis(self) -> None:
        if self._selected_file is None or self._analysis_thread is not None:
            return

        network_checks = self.network_checks_box.isChecked()

        self.statusBar().showMessage(self._t("analyzing"))
        self._clear_technical_log()
        self._log_event("LOAD", f"Selected source: {self._selected_file.name}", "normal")
        self._log_event(
            "PRIVACY",
            self._t("log_privacy_start", dns=self._t("on") if network_checks else self._t("off")),
            "normal",
        )
        self._set_busy(True)

        thread = QThread(self)
        worker = _AnalysisWorker(self._selected_file, network_checks)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.finished.connect(self._on_analysis_finished)
        worker.failed.connect(self._on_analysis_failed)
        worker.finished.connect(thread.quit)
        worker.failed.connect(thread.quit)
        thread.finished.connect(self._on_analysis_thread_done)

        self._analysis_thread = thread
        self._analysis_worker = worker
        thread.start()

    def _set_busy(self, busy: bool) -> None:
        self.analyze_button.setEnabled(not busy and self._selected_file is not None)
        self.open_button.setEnabled(not busy)
        self.drop_area.setEnabled(not busy)
        self.network_checks_box.setEnabled(not busy)
        if busy:
            QApplication.setOverrideCursor(Qt.WaitCursor)
        else:
            QApplication.restoreOverrideCursor()

    def _on_analysis_thread_done(self) -> None:
        if self._analysis_thread is not None:
            self._analysis_thread.deleteLater()
        if self._analysis_worker is not None:
            self._analysis_worker.deleteLater()
        self._analysis_thread = None
        self._analysis_worker = None
        self._set_busy(False)

    def _on_analysis_failed(self, message: str) -> None:
        QMessageBox.critical(self, self._t("analysis_error"), message)
        self.statusBar().showMessage(self._t("analysis_failed"))

    def _on_analysis_finished(self, analysis) -> None:
        self._analysis = analysis
        self._populate_result()
        self._build_analysis_technical_log()
        self.export_pdf_button.setEnabled(True)
        self.export_html_button.setEnabled(True)
        self.feedback_buttons.setExclusive(False)
        for button in self.feedback_buttons.buttons():
            button.setChecked(False)
        self.feedback_buttons.setExclusive(True)
        self.feedback_save_button.setEnabled(False)
        self.statusBar().showMessage(self._t("analysis_complete"))

    def _populate_result(self) -> None:
        analysis = self._analysis

        if analysis is None:
            return

        summary_intro, summary_bullets = _build_human_summary(analysis, self.language)

        if analysis.verdict == "SAFE":
            summary_label = self._t("verdict_safe")
            summary_style = (
                "font-size: 20px; font-weight: bold; color: #0a7a22; "
                "border: 2px solid #0a7a22; border-radius: 8px; padding: 8px;"
            )
        elif analysis.verdict == "SUSPICIOUS":
            summary_label = self._t("verdict_suspicious")
            summary_style = (
                "font-size: 20px; font-weight: bold; color: #b36b00; "
                "border: 2px solid #b36b00; border-radius: 8px; padding: 8px;"
            )
        else:
            summary_label = self._t("verdict_dangerous")
            summary_style = (
                "font-size: 20px; font-weight: bold; color: #b00020; "
                "border: 2px solid #b00020; border-radius: 8px; padding: 8px;"
            )

        self.summary_verdict_label.setText(summary_label)
        self.summary_verdict_label.setStyleSheet(summary_style)

        # Bullets can contain sender-controlled text (domains, brand names):
        # escape it before handing it to the rich-text widget.
        summary_html = (
            f"<p><b>{html.escape(summary_intro)}</b></p>"
            + f"<p><b>{html.escape(self._t('key_findings'))}</b></p><ul>"
            + "".join(f"<li>{html.escape(item)}</li>" for item in summary_bullets)
            + "</ul>"
        )
        self.summary_text.setHtml(summary_html)

        auth = analysis.authentication or {}
        suspicious_urls = sum(1 for item in analysis.urls if item.suspicious)
        suspicious_attachments = sum(1 for item in analysis.attachments if item.suspicious)

        self.score_chip.setText(self._t("chip_score", score=analysis.score))
        self.spf_chip.setText(f"SPF: {str(auth.get('spf') or 'unknown').upper()}")
        self.dkim_chip.setText(f"DKIM: {str(auth.get('dkim') or 'unknown').upper()}")
        self.dmarc_chip.setText(f"DMARC: {str(auth.get('dmarc') or 'unknown').upper()}")
        self.urls_chip.setText(
            self._t("chip_urls", total=len(analysis.urls), suspicious=suspicious_urls)
        )
        self.attachments_chip.setText(
            self._t(
                "chip_attachments",
                total=len(analysis.attachments),
                suspicious=suspicious_attachments,
            )
        )

        self.verdict_label.setText(analysis.verdict)
        self.score_label.setText(f"{analysis.score}/100")
        self.origin_ip_label.setText(
            str(analysis.received_chain.get("originating_ip") or "-")
        )

        if analysis.verdict == "DANGEROUS":
            self.verdict_label.setStyleSheet(
                "font-weight: bold; color: #b00020;"
            )
        elif analysis.verdict == "SUSPICIOUS":
            self.verdict_label.setStyleSheet(
                "font-weight: bold; color: #b36b00;"
            )
        else:
            self.verdict_label.setStyleSheet(
                "font-weight: bold; color: #0a7a22;"
            )

        header_lines = [
            f"From: {analysis.headers.from_header}",
            f"Reply-To: {analysis.headers.reply_to}",
            f"Return-Path: {analysis.headers.return_path}",
            f"Subject: {analysis.headers.subject}",
            f"Message-ID: {analysis.headers.message_id}",
            "",
            "Received:",
            *analysis.headers.received_headers,
        ]
        self.headers_text.setPlainText("\n".join(header_lines))

        auth = analysis.authentication
        alignment = auth.get("alignment", {})

        lang = self.language
        dns = auth.get("dns_checks") or {}
        if dns.get("enabled"):
            dns_value = "; ".join(
                f"{name.upper()}: {(dns.get(name) or {}).get('status', '-')}"
                for name in ("spf", "dmarc")
            )
        else:
            dns_value = self._t("dns_disabled")

        auth_rows = [
            ("SPF", _friendly_auth_value("SPF", auth.get("spf"), lang)),
            ("DKIM", _friendly_auth_value("DKIM", auth.get("dkim"), lang)),
            ("DMARC", _friendly_auth_value("DMARC", auth.get("dmarc"), lang)),
            (
                self._t("auth_dkim_domain"),
                _friendly_auth_value("DKIM domain", auth.get("dkim_domain"), lang),
            ),
            (
                self._t("auth_spf_alignment"),
                _friendly_auth_value("SPF aligned", alignment.get("spf_aligned"), lang),
            ),
            (
                self._t("auth_dkim_alignment"),
                _friendly_auth_value("DKIM aligned", alignment.get("dkim_aligned"), lang),
            ),
            (self._t("auth_server"), str(auth.get("authserv_id") or "-")),
            (self._t("auth_ignored"), str(len(auth.get("ignored_headers") or []))),
            (self._t("auth_dns"), dns_value),
        ]

        self.auth_table.setRowCount(len(auth_rows))

        for row, (name, value) in enumerate(auth_rows):
            self.auth_table.setItem(row, 0, QTableWidgetItem(str(name)))
            self.auth_table.setItem(row, 1, QTableWidgetItem(str(value)))

        self.auth_table.resizeColumnsToContents()

        self.urls_list.clear()

        for item in analysis.urls:
            reasons = "; ".join(item.reasons) if item.reasons else self._t("no_warnings")
            link_text = f"{self._t('link_text')}: {item.link_text}\n" if item.link_text else ""
            self.urls_list.addItem(
                f"{item.url}\n"
                f"{self._t('host')}: {item.hostname}\n"
                f"{link_text}"
                f"{self._t('source')}: {item.source}\n"
                f"{self._t('suspicious')}: {item.suspicious}\n"
                f"{reasons}"
            )

        self.attachments_list.clear()

        for item in analysis.attachments:
            reasons = "; ".join(item.reasons) if item.reasons else self._t("no_warnings")
            self.attachments_list.addItem(
                f"{item.filename}\n"
                f"{self._t('type')}: {item.content_type}\n"
                f"{self._t('size')}: {item.size} {self._t('bytes')}\n"
                f"SHA-256: {item.sha256}\n"
                f"{self._t('suspicious')}: {item.suspicious}\n"
                f"{reasons}"
            )

        self.findings_list.clear()

        for reason in analysis.reasons:
            explanation = explain_finding(reason, self.language)
            self.findings_list.addItem(
                f"{reason}\n{self._t('what_it_means_prefix')} {explanation}"
            )

    def _save_feedback(self) -> None:
        if self._analysis is None:
            return

        selected = self.feedback_buttons.checkedButton()
        if selected is None:
            return

        value = selected.property("feedback_value")

        self._log_event("NETWORK", "Submitting feedback to Supabase RPC: submit_scan_feedback", "normal")
        self._log_event("NETWORK", "Payload fields: app_version, engine_version, verdict, score, feedback, finding_codes, url_rule_codes, attachment_rule_codes, spf, dkim, dmarc", "detailed")
        url_codes = sorted({c for u in self._analysis.urls for c in u.rule_codes})
        attachment_codes = sorted({c for a in self._analysis.attachments for c in a.rule_codes})
        self._log_event("NETWORK", "Not transmitted: message body, subject, sender/recipient addresses, full URLs, attachment contents, attachment hashes, source file path.", "detailed")

        threading.Thread(
            target=submit_scan_feedback_cloud,
            kwargs={
                "verdict": self._analysis.verdict,
                "score": self._analysis.score,
                "feedback": str(value),
                "app_version": __version__,
                "authentication": self._analysis.authentication or {},
                "finding_codes": list(self._analysis.rule_codes),
                "url_rule_codes": url_codes,
                "attachment_rule_codes": attachment_codes,
            },
            daemon=True,
        ).start()

        self.statusBar().showMessage(self._t("feedback_sent"))

        self.feedback_save_button.setEnabled(False)

    def closeEvent(self, event) -> None:
        if self._analysis_thread is not None:
            self._analysis_thread.quit()
            self._analysis_thread.wait(10000)

        if should_prompt_for_app_rating():
            AppRatingDialog(self, self.language).exec()
            mark_app_rating_prompted()

        event.accept()

    def _export_pdf(self) -> None:
        if self._analysis is None:
            return

        filename, _ = QFileDialog.getSaveFileName(
            self,
            self._t("export_pdf_title"),
            "phishing-report.pdf",
            "PDF files (*.pdf)",
        )

        if not filename:
            return

        report = build_report_model(self._analysis, self.language)
        write_pdf_report(report, filename)
        self.statusBar().showMessage(self._t("pdf_exported", path=filename))

    def _export_html(self) -> None:
        if self._analysis is None:
            return

        filename, _ = QFileDialog.getSaveFileName(
            self,
            self._t("export_html_title"),
            "phishing-report.html",
            "HTML files (*.html)",
        )

        if not filename:
            return

        report = build_report_model(self._analysis, self.language)
        write_html_report(report, filename)
        self.statusBar().showMessage(self._t("html_exported", path=filename))


def main(language: str | None = None) -> int:
    app = QApplication(sys.argv)
    window = MainWindow(language)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())

