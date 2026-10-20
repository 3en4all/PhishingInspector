from __future__ import annotations

import html
import os
import sys
import threading
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QObject, QSize, Qt, QThread, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices, QIcon, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QCheckBox,
    QDialog,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QTextEdit,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from . import gui_theme as theme
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

# Spacing scale used throughout the window (px).
SPACE_S = 8
SPACE_M = 12
SPACE_L = 16
SPACE_XL = 24


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


def _build_summary_items(analysis, language: str = "pl") -> tuple[str, list[tuple[str, str]]]:
    """Plain-language summary: intro sentence and (level, text) bullets.

    The level ("ok", "warning", "danger", "info", "neutral") only picks the
    bullet colour in the GUI; it does not change the verdict.
    """
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

    items: list[tuple[str, str]] = []

    scored = [f for f in getattr(analysis, "findings", []) if f.points > 0]
    if scored and verdict != "SAFE":
        top = max(scored, key=lambda f: f.points)
        # Rule messages are written in English; the Polish UI shows the
        # Polish explanation of the rule instead, when one is known.
        reason = top.message
        if normalize_language(language) != "en":
            explanation = explain_finding(top.message, language)
            if explanation != explain_finding("", language):
                reason = explanation
        items.append(
            ("danger" if verdict == "DANGEROUS" else "warning", t("bullet_top", reason=reason))
        )

    items.append(
        (
            "ok" if auth_pass_count == 3 else "warning" if auth_pass_count == 0 else "info",
            t("bullet_auth", count=auth_pass_count),
        )
    )

    if urls:
        items.append(
            (
                "danger" if suspicious_urls else "ok",
                t("bullet_links", total=len(urls), suspicious=suspicious_urls),
            )
        )
    else:
        items.append(("neutral", t("bullet_no_links")))

    if attachments:
        archive_exts = {".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".iso", ".img", ".vhd", ".vhdx", ".cab"}
        archive_count = sum(
            1
            for item in attachments
            if Path(item.filename).suffix.lower() in archive_exts
        )

        items.append(
            (
                "danger" if suspicious_attachments else "info",
                t("bullet_attachments", total=len(attachments), suspicious=suspicious_attachments),
            )
        )

        if archive_count:
            items.append(("warning", t("bullet_archives", count=archive_count)))

        items.append(("warning", t("bullet_attachment_warning")))
    else:
        items.append(("neutral", t("bullet_no_attachments")))

    if findings:
        items.append(("info", t("bullet_findings", count=len(findings))))

    for note in getattr(analysis, "limitations", []) or []:
        items.append(("warning", f"{t('limitations')} {note}"))

    return intro, items


def _build_human_summary(analysis, language: str = "pl") -> tuple[str, list[str]]:
    intro, items = _build_summary_items(analysis, language)
    return intro, [item for _level, item in items]


class DropArea(QFrame):
    """Compact drop zone; shows the chosen file as a chip."""

    def __init__(self, on_file_dropped, label: str = "Drop .eml or .msg file here", hint: str = "") -> None:
        super().__init__()
        self._on_file_dropped = on_file_dropped

        self.setObjectName("dropZone")
        self.setAcceptDrops(True)
        self.setFixedHeight(60)
        self.setCursor(Qt.PointingHandCursor)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 6, 16, 6)
        layout.setSpacing(12)

        self.icon_label = QLabel()
        self.icon_label.setPixmap(theme.envelope_icon(theme.MUTED, 32))
        self.icon_label.setStyleSheet("background: transparent; border: none;")
        layout.addWidget(self.icon_label)

        texts = QVBoxLayout()
        texts.setSpacing(2)
        self.title_label = QLabel(label)
        self.title_label.setObjectName("dropTitle")
        self.hint_label = QLabel(hint)
        self.hint_label.setObjectName("dropHint")
        for widget in (self.title_label, self.hint_label):
            widget.setStyleSheet("background: transparent; border: none;")
            texts.addWidget(widget)
        layout.addLayout(texts, 1)

        self.file_chip = QLabel()
        self.file_chip.setObjectName("fileChip")
        self.file_chip.setVisible(False)
        layout.addWidget(self.file_chip, 0, Qt.AlignVCenter)

    def show_file(self, path: Path, change_hint: str) -> None:
        self.file_chip.setText(path.name)
        self.file_chip.setToolTip(str(path))
        self.file_chip.setVisible(True)
        self.hint_label.setText(change_hint)

    def _set_active(self, active: bool) -> None:
        self.setProperty("active", "true" if active else "false")
        self.style().unpolish(self)
        self.style().polish(self)

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.LeftButton:
            window = self.window()
            if hasattr(window, "_open_file_dialog"):
                window._open_file_dialog()
        super().mousePressEvent(event)

    def dragEnterEvent(self, event) -> None:
        path = extract_supported_drop_path(event)

        if path is not None:
            event.setDropAction(Qt.CopyAction)
            event.accept()
            self._set_active(True)
        else:
            event.ignore()

    def dragMoveEvent(self, event) -> None:
        path = extract_supported_drop_path(event)

        if path is not None:
            event.setDropAction(Qt.CopyAction)
            event.accept()
        else:
            event.ignore()

    def dragLeaveEvent(self, event) -> None:
        self._set_active(False)
        super().dragLeaveEvent(event)

    def dropEvent(self, event) -> None:
        self._set_active(False)
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


class MetricTile(QFrame):
    """One equal-size dashboard tile: caption, value and a short note."""

    def __init__(self, caption: str) -> None:
        super().__init__()
        self.setObjectName("tile")
        self.setMinimumHeight(62)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 6, 12, 6)
        layout.setSpacing(0)

        self.caption_label = QLabel(caption.upper())
        self.caption_label.setObjectName("tileLabel")
        self.value_label = QLabel("—")
        self.value_label.setObjectName("tileValue")
        self.sub_label = QLabel("")
        self.sub_label.setObjectName("tileSub")
        for widget in (self.caption_label, self.value_label, self.sub_label):
            layout.addWidget(widget)

    def set_value(self, value: str, level: str = "neutral", sub: str = "", tooltip: str = "") -> None:
        color = theme.LEVEL_COLORS.get(level, theme.TEXT) if level != "neutral" else theme.TEXT
        self.value_label.setText(value)
        self.value_label.setStyleSheet(f"color: {color};")
        self.sub_label.setText(sub)
        self.setToolTip(tooltip)

    def text(self) -> str:
        return f"{self.caption_label.text()}: {self.value_label.text()}"


def _card(name: str = "card") -> tuple[QFrame, QVBoxLayout]:
    frame = QFrame()
    frame.setObjectName(name)
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(SPACE_L, SPACE_M, SPACE_L, SPACE_L)
    layout.setSpacing(SPACE_S)
    return frame, layout


def _caption(label: str) -> QLabel:
    widget = QLabel(label.upper())
    widget.setObjectName("cardCaption")
    return widget


def _auth_level(value) -> str:
    value = str(value or "unknown").lower()
    if value == "pass":
        return "ok"
    if value in {"fail", "permerror", "temperror"}:
        return "danger"
    if value in {"softfail", "neutral"}:
        return "warning"
    return "neutral"


class MainWindow(QMainWindow):
    def __init__(self, language: str | None = None) -> None:
        super().__init__()

        self.language = normalize_language(
            language or os.environ.get("PHISHING_INSPECTOR_LANG")
        )
        self._analysis_thread: QThread | None = None
        self._analysis_worker: _AnalysisWorker | None = None

        self.setWindowTitle("Phishing Inspector")
        self.resize(1280, 800)
        self.setMinimumSize(1100, 680)
        self.setAcceptDrops(True)
        logo = asset_path("app-logo.png")
        if logo.is_file():
            self.setWindowIcon(QIcon(str(logo)))

        self._selected_file: Path | None = None
        self._analysis = None
        self._technical_log_entries: list[tuple[str, str, str]] = []
        self._technical_log_level = "Detailed"
        self._technical_log_visible = False
        self._theme_name = theme.DEFAULT_ACCENT

        root = QWidget()
        root.setObjectName("root")
        self.setCentralWidget(root)

        outer = QVBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        outer.addWidget(self._build_header())

        layout = QVBoxLayout()
        layout.setContentsMargins(SPACE_XL, SPACE_L, SPACE_XL, SPACE_M)
        layout.setSpacing(SPACE_M)
        outer.addLayout(layout, 1)

        layout.addWidget(self._build_input_card())

        result_row = QHBoxLayout()
        result_row.setSpacing(SPACE_M)
        result_row.addWidget(self._build_hero_card(), 5)
        result_row.addWidget(self._build_findings_card(), 6)
        layout.addLayout(result_row, 0)

        self._build_tabs()
        self._build_technical_log_panel()

        self.main_content_row = QHBoxLayout()
        self.main_content_row.setSpacing(SPACE_M)
        self.main_content_row.addWidget(self.tabs, 1)
        self.main_content_row.addWidget(self.technical_log_panel, 0)
        layout.addLayout(self.main_content_row, 1)

        layout.addWidget(self._build_feedback_bar())

        self._build_status_bar()

        # The Help menu stays available (Alt key, accessibility tools); the
        # visible entry point is the header button.
        help_menu = self.menuBar().addMenu(self._t("menu_help"))
        self.about_action = help_menu.addAction(self._t("menu_about"))
        self.about_action.triggered.connect(self._show_about)
        self.menuBar().setVisible(False)

        self._show_empty_result()
        self._apply_theme(theme.DEFAULT_ACCENT)

    # ----- layout -------------------------------------------------------

    def _build_header(self) -> QFrame:
        header = QFrame()
        header.setObjectName("header")
        header.setFixedHeight(58)
        row = QHBoxLayout(header)
        row.setContentsMargins(SPACE_XL, SPACE_S, SPACE_XL, SPACE_S)
        row.setSpacing(SPACE_M)

        logo = QLabel()
        logo_path = asset_path("app-logo.png")
        if logo_path.is_file():
            pixmap = QPixmap(str(logo_path))
            ratio = self.devicePixelRatioF() or 1.0
            pixmap = pixmap.scaled(
                int(40 * ratio), int(40 * ratio), Qt.KeepAspectRatio, Qt.SmoothTransformation
            )
            pixmap.setDevicePixelRatio(ratio)
            logo.setPixmap(pixmap)
        logo.setFixedSize(40, 40)
        row.addWidget(logo)

        titles = QVBoxLayout()
        titles.setSpacing(0)
        title_row = QHBoxLayout()
        title_row.setSpacing(SPACE_S)
        title = QLabel("Phishing Inspector")
        title.setObjectName("appTitle")
        version = QLabel(f"v{__version__}")
        version.setObjectName("versionPill")
        title_row.addWidget(title)
        title_row.addWidget(version, 0, Qt.AlignVCenter)
        title_row.addStretch(1)
        titles.addLayout(title_row)
        subtitle = QLabel(self._t("app_subtitle"))
        subtitle.setObjectName("appSubtitle")
        titles.addWidget(subtitle)
        row.addLayout(titles, 1)

        self.theme_buttons = {}
        for theme_name, theme_color in theme.ACCENTS.items():
            button = QPushButton()
            button.setObjectName("accentDot")
            button.setCheckable(True)
            button.setFixedSize(18, 18)
            button.setCursor(Qt.PointingHandCursor)
            button.setToolTip(self._t("accent_tip", name=theme_name))
            button.setAccessibleName(theme_name)
            button.setStyleSheet(f"QPushButton#accentDot {{ background: {theme_color}; }}")
            button.clicked.connect(
                lambda _checked=False, name=theme_name: self._apply_theme(name)
            )
            self.theme_buttons[theme_name] = button
            row.addWidget(button)

        row.addSpacing(SPACE_S)
        self.help_button = QPushButton(self._t("header_help"))
        self.help_button.setObjectName("ghostButton")
        self.help_button.setCursor(Qt.PointingHandCursor)
        self.help_button.clicked.connect(self._show_about)
        row.addWidget(self.help_button)
        return header

    def _build_input_card(self) -> QFrame:
        card, layout = _card()
        layout.setContentsMargins(SPACE_L, SPACE_M, SPACE_L, SPACE_S)

        row = QHBoxLayout()
        row.setSpacing(SPACE_M)
        self.drop_area = DropArea(self._select_file, self._t("drop_here"), self._t("drop_hint"))
        self.file_label = self.drop_area.file_chip
        row.addWidget(self.drop_area, 1)

        self.open_button = QPushButton(self._t("open_file"))
        self.open_button.setObjectName("secondaryButton")
        self.open_button.setCursor(Qt.PointingHandCursor)
        self.open_button.setMinimumHeight(46)
        self.open_button.clicked.connect(self._open_file_dialog)
        row.addWidget(self.open_button)

        self.analyze_button = QPushButton(self._t("analyze"))
        self.analyze_button.setObjectName("primaryButton")
        self.analyze_button.setCursor(Qt.PointingHandCursor)
        self.analyze_button.setMinimumSize(170, 46)
        self.analyze_button.setEnabled(False)
        self.analyze_button.clicked.connect(self._run_analysis)
        row.addWidget(self.analyze_button)
        layout.addLayout(row)

        options = QHBoxLayout()
        options.setSpacing(SPACE_S)
        self.network_checks_box = QCheckBox(self._t("network_checks"))
        self.network_checks_box.setChecked(False)
        self.network_checks_box.setToolTip(self._t("network_checks_tip"))
        options.addWidget(self.network_checks_box)
        options.addStretch(1)

        self.technical_log_button = QPushButton(self._t("technical_log"))
        self.technical_log_button.setObjectName("ghostButton")
        self.technical_log_button.setCheckable(True)
        self.technical_log_button.clicked.connect(self._toggle_technical_log)
        options.addWidget(self.technical_log_button)

        self.export_pdf_button = QPushButton(self._t("export_pdf"))
        self.export_pdf_button.setObjectName("ghostButton")
        self.export_pdf_button.clicked.connect(self._export_pdf)
        self.export_pdf_button.setEnabled(False)
        options.addWidget(self.export_pdf_button)

        self.export_html_button = QPushButton(self._t("export_html"))
        self.export_html_button.setObjectName("ghostButton")
        self.export_html_button.clicked.connect(self._export_html)
        self.export_html_button.setEnabled(False)
        options.addWidget(self.export_html_button)
        layout.addLayout(options)
        return card

    def _build_hero_card(self) -> QFrame:
        self.hero_card, layout = _card("heroCard")
        layout.setSpacing(SPACE_S)
        layout.addWidget(_caption(self._t("result_card")))

        verdict_row = QHBoxLayout()
        verdict_row.setSpacing(SPACE_L)
        self.verdict_icon = QLabel()
        self.verdict_icon.setFixedSize(56, 56)
        verdict_row.addWidget(self.verdict_icon, 0, Qt.AlignTop)

        verdict_texts = QVBoxLayout()
        verdict_texts.setSpacing(2)
        self.summary_verdict_label = QLabel(self._t("no_analysis"))
        self.summary_verdict_label.setObjectName("verdictText")
        self.verdict_sub_label = QLabel(self._t("verdict_none_sub"))
        self.verdict_sub_label.setObjectName("verdictSub")
        self.verdict_sub_label.setWordWrap(True)
        verdict_texts.addWidget(self.summary_verdict_label)
        verdict_texts.addWidget(self.verdict_sub_label)
        verdict_texts.addStretch(1)
        verdict_row.addLayout(verdict_texts, 1)

        score_box = QVBoxLayout()
        score_box.setSpacing(0)
        score_caption = QLabel(self._t("risk_score").upper())
        score_caption.setObjectName("scoreCaption")
        score_caption.setAlignment(Qt.AlignRight)
        score_line = QHBoxLayout()
        score_line.setSpacing(2)
        score_line.addStretch(1)
        self.score_label = QLabel("—")
        self.score_label.setObjectName("scoreValue")
        score_max = QLabel("/100")
        score_max.setObjectName("scoreMax")
        score_line.addWidget(self.score_label, 0, Qt.AlignBottom)
        score_line.addWidget(score_max, 0, Qt.AlignBottom)
        score_box.addWidget(score_caption)
        score_box.addLayout(score_line)
        self.risk_bar = QProgressBar()
        self.risk_bar.setObjectName("riskBar")
        self.risk_bar.setRange(0, 100)
        self.risk_bar.setTextVisible(False)
        self.risk_bar.setFixedHeight(6)
        self.risk_bar.setFixedWidth(150)
        score_box.addSpacing(SPACE_S)
        score_box.addWidget(self.risk_bar, 0, Qt.AlignRight)
        verdict_row.addLayout(score_box)
        layout.addLayout(verdict_row)

        grid = QGridLayout()
        grid.setHorizontalSpacing(SPACE_S)
        grid.setVerticalSpacing(SPACE_S)
        self.spf_chip = MetricTile("SPF")
        self.dkim_chip = MetricTile("DKIM")
        self.dmarc_chip = MetricTile("DMARC")
        self.urls_chip = MetricTile(self._t("tile_links"))
        self.attachments_chip = MetricTile(self._t("tile_attachments"))
        self.origin_ip_label = MetricTile(self._t("tile_origin_ip"))
        tiles = (
            self.spf_chip,
            self.dkim_chip,
            self.dmarc_chip,
            self.urls_chip,
            self.attachments_chip,
            self.origin_ip_label,
        )
        for index, tile in enumerate(tiles):
            grid.addWidget(tile, index // 3, index % 3)
        for column in range(3):
            grid.setColumnStretch(column, 1)
        layout.addLayout(grid)
        return self.hero_card

    def _build_findings_card(self) -> QFrame:
        card, layout = _card()
        layout.setSpacing(SPACE_S)
        layout.addWidget(_caption(self._t("what_it_means")))

        self.summary_intro_label = QLabel(self._t("findings_placeholder"))
        self.summary_intro_label.setObjectName("bodyText")
        self.summary_intro_label.setWordWrap(True)
        layout.addWidget(self.summary_intro_label)

        layout.addSpacing(SPACE_S)
        layout.addWidget(_caption(self._t("key_findings")))

        self.summary_text = QTextBrowser()
        self.summary_text.setObjectName("findingsView")
        self.summary_text.setOpenLinks(False)
        self.summary_text.setMinimumHeight(120)
        self.summary_text.document().setDocumentMargin(0)
        layout.addWidget(self.summary_text, 1)
        return card

    def _build_tabs(self) -> None:
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(False)
        self.tabs.setMinimumHeight(130)

        self.headers_text = QTextEdit()
        self.headers_text.setObjectName("techText")
        self.headers_text.setReadOnly(True)
        self.tabs.addTab(self.headers_text, self._t("tab_headers"))

        self.auth_table = QTableWidget(0, 2)
        self.auth_table.setHorizontalHeaderLabels([self._t("field"), self._t("value")])
        self.auth_table.verticalHeader().setVisible(False)
        self.auth_table.verticalHeader().setDefaultSectionSize(34)
        self.auth_table.horizontalHeader().setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.auth_table.horizontalHeader().setStretchLastSection(True)
        self.auth_table.setShowGrid(False)
        self.auth_table.setAlternatingRowColors(False)
        self.auth_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.auth_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.tabs.addTab(self.auth_table, self._t("tab_auth"))

        self.urls_list = QListWidget()
        self.tabs.addTab(self.urls_list, self._t("tab_urls"))

        self.attachments_list = QListWidget()
        self.tabs.addTab(self.attachments_list, self._t("tab_attachments"))

        self.findings_list = QListWidget()
        self.tabs.addTab(self.findings_list, self._t("tab_findings"))

        for widget in (self.urls_list, self.attachments_list, self.findings_list):
            widget.setWordWrap(True)
            widget.setIconSize(QSize(12, 12))

    def _build_technical_log_panel(self) -> None:
        self.technical_log_panel = QFrame()
        self.technical_log_panel.setObjectName("logPanel")
        self.technical_log_panel.setMinimumWidth(360)
        self.technical_log_panel.setMaximumWidth(460)
        technical_log_layout = QVBoxLayout(self.technical_log_panel)
        technical_log_layout.setContentsMargins(SPACE_M, SPACE_M, SPACE_M, SPACE_M)
        technical_log_layout.setSpacing(SPACE_S)

        log_controls = QHBoxLayout()
        log_controls.setSpacing(4)
        self.log_normal_button = QPushButton(self._t("log_normal"))
        self.log_detailed_button = QPushButton(self._t("log_detailed"))
        self.copy_log_button = QPushButton(self._t("copy_log"))
        for button in (self.log_normal_button, self.log_detailed_button, self.copy_log_button):
            button.setObjectName("ghostButton")
            log_controls.addWidget(button)
            if button is self.log_detailed_button:
                log_controls.addStretch(1)
        self.log_normal_button.setCheckable(True)
        self.log_detailed_button.setCheckable(True)
        self.log_detailed_button.setChecked(True)

        self.log_normal_button.clicked.connect(
            lambda: self._set_technical_log_level("Normal")
        )
        self.log_detailed_button.clicked.connect(
            lambda: self._set_technical_log_level("Detailed")
        )
        self.copy_log_button.clicked.connect(self._copy_technical_log)
        technical_log_layout.addLayout(log_controls)

        self.technical_log_text = QTextEdit()
        self.technical_log_text.setObjectName("logText")
        self.technical_log_text.setReadOnly(True)
        self.technical_log_text.setMinimumHeight(140)
        technical_log_layout.addWidget(self.technical_log_text)

        self.technical_log_panel.setVisible(False)

    def _build_feedback_bar(self) -> QFrame:
        self.feedback_group = QFrame()
        self.feedback_group.setObjectName("feedbackBar")
        row = QHBoxLayout(self.feedback_group)
        row.setContentsMargins(SPACE_M, 4, SPACE_M, 4)
        row.setSpacing(SPACE_S)

        self.feedback_toggle = QToolButton()
        self.feedback_toggle.setObjectName("feedbackToggle")
        self.feedback_toggle.setText(self._t("feedback_toggle"))
        self.feedback_toggle.setCheckable(True)
        self.feedback_toggle.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.feedback_toggle.setArrowType(Qt.RightArrow)
        self.feedback_toggle.setCursor(Qt.PointingHandCursor)
        self.feedback_toggle.toggled.connect(self._set_feedback_expanded)
        row.addWidget(self.feedback_toggle)

        self.feedback_body = QWidget()
        body = QHBoxLayout(self.feedback_body)
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(SPACE_S)
        question = QLabel(self._t("feedback_group"))
        question.setObjectName("mutedText")
        body.addWidget(question)
        body.addSpacing(SPACE_S)

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
            button.setCursor(Qt.PointingHandCursor)
            self.feedback_buttons.addButton(button)
            body.addWidget(button)

        body.addStretch(1)
        self.feedback_save_button = QPushButton(self._t("feedback_save"))
        self.feedback_save_button.setToolTip(self._t("feedback_tip"))
        self.feedback_save_button.clicked.connect(self._save_feedback)
        self.feedback_save_button.setEnabled(False)
        body.addWidget(self.feedback_save_button)
        row.addWidget(self.feedback_body, 1)
        row.addStretch(0)
        self.feedback_body.setVisible(False)

        self.feedback_buttons.buttonClicked.connect(
            lambda _button: self.feedback_save_button.setEnabled(True)
        )
        return self.feedback_group

    def _build_status_bar(self) -> None:
        self.statusBar().setSizeGripEnabled(False)
        self.statusBar().setContentsMargins(SPACE_M, 2, SPACE_M, 2)
        self.statusBar().showMessage(self._t("ready"))

        self.branding_label = QLabel(
            '<a href="https://3en4all.github.io/" style="text-decoration:none; '
            f'color:{theme.MUTED};">{html.escape(self._t("branding"))}</a>'
        )
        self.branding_label.setOpenExternalLinks(True)
        self.branding_label.setContentsMargins(0, 0, SPACE_M, 0)
        self.statusBar().addPermanentWidget(self.branding_label, 0)

        self.buycoffee_button = QPushButton()
        self.buycoffee_button.setObjectName("coffeeButton")
        self.buycoffee_button.setToolTip(self._t("buycoffee_tip"))
        self.buycoffee_button.setCursor(Qt.PointingHandCursor)
        self.buycoffee_button.setFixedSize(110, 29)
        self.buycoffee_button.setIcon(
            QIcon(str(asset_path(self._t("buycoffee_asset"))))
        )
        self.buycoffee_button.setIconSize(QSize(110, 29))
        self.buycoffee_button.clicked.connect(
            lambda: QDesktopServices.openUrl(
                QUrl("https://buycoffee.to/3en4all")
            )
        )
        self.statusBar().addPermanentWidget(self.buycoffee_button, 0)

    def _set_feedback_expanded(self, expanded: bool) -> None:
        self.feedback_body.setVisible(expanded)
        self.feedback_toggle.setArrowType(Qt.DownArrow if expanded else Qt.RightArrow)

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
        if theme_name not in theme.ACCENTS:
            theme_name = theme.DEFAULT_ACCENT
        self._theme_name = theme_name

        for name, button in self.theme_buttons.items():
            button.setChecked(name == theme_name)

        self.setStyleSheet(theme.stylesheet(theme.ACCENTS[theme_name]))

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
        self.drop_area.show_file(resolved, self._t("drop_change"))
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

    def _show_empty_result(self) -> None:
        self.hero_card.setStyleSheet(theme.hero_style("neutral"))
        self.verdict_icon.setPixmap(theme.verdict_icon("neutral", 56))
        self.summary_verdict_label.setText(self._t("no_analysis"))
        self.summary_verdict_label.setStyleSheet(f"color: {theme.MUTED};")
        self.verdict_sub_label.setText(self._t("verdict_none_sub"))
        self.score_label.setText("—")
        self.score_label.setStyleSheet(f"color: {theme.MUTED};")
        self.risk_bar.setValue(0)
        for tile in (
            self.spf_chip,
            self.dkim_chip,
            self.dmarc_chip,
            self.urls_chip,
            self.attachments_chip,
            self.origin_ip_label,
        ):
            tile.set_value("—")
        self.summary_intro_label.setText(self._t("findings_placeholder"))
        self.summary_text.clear()

    def _yes_no(self, value: bool) -> str:
        return self._t("yes") if value else self._t("no")

    def _auth_short(self, value) -> str:
        normalized = str(value or "unknown").strip().lower()
        key = f"auth_short_{normalized}"
        label = self._t(key)
        return label if label != key else normalized.capitalize()

    def _count_tile(self, tile: MetricTile, total: int, suspicious: int) -> None:
        if not total:
            tile.set_value("0", "neutral", self._t("tile_none"))
            return
        tile.set_value(
            str(total),
            "danger" if suspicious else "ok",
            self._t("tile_suspicious", count=suspicious),
        )

    def _populate_result(self) -> None:
        analysis = self._analysis

        if analysis is None:
            return

        summary_intro, summary_items = _build_summary_items(analysis, self.language)

        level = theme.VERDICT_LEVELS.get(analysis.verdict, "danger")
        color = theme.LEVEL_COLORS[level]
        verdict_key = {
            "SAFE": "safe",
            "SUSPICIOUS": "suspicious",
        }.get(analysis.verdict, "dangerous")

        self.hero_card.setStyleSheet(theme.hero_style(level))
        self.verdict_icon.setPixmap(theme.verdict_icon(level, 56))
        self.summary_verdict_label.setText(self._t(f"verdict_{verdict_key}"))
        self.summary_verdict_label.setStyleSheet(f"color: {color};")
        self.verdict_sub_label.setText(self._t(f"verdict_{verdict_key}_sub"))
        self.score_label.setText(str(analysis.score))
        self.score_label.setStyleSheet(f"color: {color};")
        self.risk_bar.setValue(max(0, min(100, int(analysis.score))))
        self.risk_bar.setStyleSheet(
            f"QProgressBar#riskBar::chunk {{ background: {color}; border-radius: 3px; }}"
        )

        # Bullets can contain sender-controlled text (domains, brand names):
        # escape it before handing it to the rich-text widget.
        self.summary_intro_label.setText(summary_intro)
        rows = "".join(
            "<tr>"
            f'<td width="22" valign="top" style="color:{theme.LEVEL_COLORS.get(item_level, theme.FAINT)}; '
            'font-size:15px; padding-top:1px;">●</td>'
            f'<td style="padding-bottom:7px;">{html.escape(item)}</td>'
            "</tr>"
            for item_level, item in summary_items
        )
        self.summary_text.setHtml(
            f'<table cellspacing="0" cellpadding="0" width="100%" style="color:{theme.TEXT};">'
            f"{rows}</table>"
        )

        auth = analysis.authentication or {}
        suspicious_urls = sum(1 for item in analysis.urls if item.suspicious)
        suspicious_attachments = sum(1 for item in analysis.attachments if item.suspicious)

        for tile, field, sub_key in (
            (self.spf_chip, "spf", "auth_sub_spf"),
            (self.dkim_chip, "dkim", "auth_sub_dkim"),
            (self.dmarc_chip, "dmarc", "auth_sub_dmarc"),
        ):
            value = auth.get(field)
            tile.set_value(
                self._auth_short(value),
                _auth_level(value),
                self._t(sub_key),
                _friendly_auth_value(field.upper(), value, self.language),
            )
        self._count_tile(self.urls_chip, len(analysis.urls), suspicious_urls)
        self._count_tile(self.attachments_chip, len(analysis.attachments), suspicious_attachments)
        origin_ip = analysis.received_chain.get("originating_ip")
        self.origin_ip_label.set_value(
            str(origin_ip or "—"), "neutral", self._t("tile_ip_sub"), str(origin_ip or "")
        )

        header_lines = [
            f"From:         {analysis.headers.from_header}",
            f"Reply-To:     {analysis.headers.reply_to}",
            f"Return-Path:  {analysis.headers.return_path}",
            f"Subject:      {analysis.headers.subject}",
            f"Message-ID:   {analysis.headers.message_id}",
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
            ("SPF", _friendly_auth_value("SPF", auth.get("spf"), lang), _auth_level(auth.get("spf"))),
            ("DKIM", _friendly_auth_value("DKIM", auth.get("dkim"), lang), _auth_level(auth.get("dkim"))),
            ("DMARC", _friendly_auth_value("DMARC", auth.get("dmarc"), lang), _auth_level(auth.get("dmarc"))),
            (
                self._t("auth_dkim_domain"),
                _friendly_auth_value("DKIM domain", auth.get("dkim_domain"), lang),
                "neutral",
            ),
            (
                self._t("auth_spf_alignment"),
                _friendly_auth_value("SPF aligned", alignment.get("spf_aligned"), lang),
                {True: "ok", False: "warning"}.get(alignment.get("spf_aligned"), "neutral"),
            ),
            (
                self._t("auth_dkim_alignment"),
                _friendly_auth_value("DKIM aligned", alignment.get("dkim_aligned"), lang),
                {True: "ok", False: "warning"}.get(alignment.get("dkim_aligned"), "neutral"),
            ),
            (self._t("auth_server"), str(auth.get("authserv_id") or "-"), "neutral"),
            (self._t("auth_ignored"), str(len(auth.get("ignored_headers") or [])), "neutral"),
            (self._t("auth_dns"), dns_value, "neutral"),
        ]

        self.auth_table.setRowCount(len(auth_rows))

        for row, (name, value, row_level) in enumerate(auth_rows):
            name_item = QTableWidgetItem(str(name))
            name_item.setForeground(QColor(theme.MUTED))
            value_item = QTableWidgetItem(str(value))
            if row_level != "neutral":
                value_item.setIcon(QIcon(theme.dot_icon(row_level)))
            self.auth_table.setItem(row, 0, name_item)
            self.auth_table.setItem(row, 1, value_item)

        self.auth_table.resizeColumnToContents(0)

        self.urls_list.clear()

        for item in analysis.urls:
            reasons = "; ".join(item.reasons) if item.reasons else self._t("no_warnings")
            link_text = f"{self._t('link_text')}: {item.link_text}\n" if item.link_text else ""
            entry = QListWidgetItem(
                f"{item.url}\n"
                f"{self._t('host')}: {item.hostname}\n"
                f"{link_text}"
                f"{self._t('source')}: {item.source}\n"
                f"{self._t('suspicious')}: {self._yes_no(item.suspicious)}\n"
                f"{reasons}"
            )
            entry.setIcon(QIcon(theme.dot_icon("danger" if item.suspicious else "ok")))
            self.urls_list.addItem(entry)

        self.attachments_list.clear()

        for item in analysis.attachments:
            reasons = "; ".join(item.reasons) if item.reasons else self._t("no_warnings")
            entry = QListWidgetItem(
                f"{item.filename}\n"
                f"{self._t('type')}: {item.content_type}\n"
                f"{self._t('size')}: {item.size} {self._t('bytes')}\n"
                f"SHA-256: {item.sha256}\n"
                f"{self._t('suspicious')}: {self._yes_no(item.suspicious)}\n"
                f"{reasons}"
            )
            entry.setIcon(QIcon(theme.dot_icon("danger" if item.suspicious else "ok")))
            self.attachments_list.addItem(entry)

        self.findings_list.clear()

        finding_level = "danger" if analysis.verdict == "DANGEROUS" else "warning"
        for reason in analysis.reasons:
            explanation = explain_finding(reason, self.language)
            if self.language == "en":
                body = f"{reason}\n{self._t('what_it_means_prefix')} {explanation}"
            else:
                # Rule messages are English; lead with the Polish explanation.
                body = f"{explanation}\n{self._t('technical_detail')}: {reason}"
            entry = QListWidgetItem(body)
            context_only = "context only" in reason.lower()
            entry.setIcon(QIcon(theme.dot_icon("info" if context_only else finding_level)))
            self.findings_list.addItem(entry)

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
    theme.apply_app_look(app)
    window = MainWindow(language)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())

