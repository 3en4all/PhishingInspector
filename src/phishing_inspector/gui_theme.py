"""Look of the desktop app: colour palette, the Qt style sheet and small drawn icons.

Only the GUI imports this module. Icons are painted in code, so the window
looks the same on every machine and needs no extra image files.
"""
from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPalette, QPen, QPixmap

# Base palette (dark).
BG = "#0f1115"
CARD = "#171b22"
SECTION = "#1d2330"
BORDER = "#2a3140"
TEXT = "#f3f6fb"
MUTED = "#aeb7c6"
FAINT = "#7d8799"
SAFE = "#2fbf71"
WARNING = "#f5a623"
DANGER = "#ff4d5a"
INFO = "#4da3ff"

# Accent variants the user can switch between (name -> colour).
ACCENTS = {
    "Tech Blue": INFO,
    "Emerald": SAFE,
    "Amber": WARNING,
}
DEFAULT_ACCENT = "Tech Blue"

# Colour for each state a verdict, badge or bullet can be in.
LEVEL_COLORS = {
    "ok": SAFE,
    "warning": WARNING,
    "danger": DANGER,
    "info": INFO,
    "neutral": FAINT,
}

VERDICT_LEVELS = {"SAFE": "ok", "SUSPICIOUS": "warning", "DANGEROUS": "danger"}

FONT_FAMILIES = '"Segoe UI Variable Text", "Segoe UI", "Inter", "Noto Sans", sans-serif'
MONO_FAMILIES = '"Cascadia Mono", Consolas, "DejaVu Sans Mono", monospace'


def rgba(color: str, alpha: float) -> str:
    c = QColor(color)
    return f"rgba({c.red()}, {c.green()}, {c.blue()}, {alpha})"


def dark_palette() -> QPalette:
    """Palette for widgets the style sheet does not reach (menus, tooltips, dialogs)."""
    palette = QPalette()
    roles = {
        QPalette.Window: BG,
        QPalette.WindowText: TEXT,
        QPalette.Base: CARD,
        QPalette.AlternateBase: SECTION,
        QPalette.Text: TEXT,
        QPalette.Button: SECTION,
        QPalette.ButtonText: TEXT,
        QPalette.ToolTipBase: SECTION,
        QPalette.ToolTipText: TEXT,
        QPalette.Highlight: INFO,
        QPalette.HighlightedText: BG,
        QPalette.Link: INFO,
        QPalette.PlaceholderText: FAINT,
    }
    for role, color in roles.items():
        palette.setColor(role, QColor(color))
    palette.setColor(QPalette.Disabled, QPalette.Text, QColor(FAINT))
    palette.setColor(QPalette.Disabled, QPalette.ButtonText, QColor(FAINT))
    palette.setColor(QPalette.Disabled, QPalette.WindowText, QColor(FAINT))
    return palette


def apply_app_look(app) -> None:
    """Fusion style + dark palette: predictable under a style sheet on every Windows version."""
    app.setStyle("Fusion")
    app.setPalette(dark_palette())
    font = QFont()
    font.setFamilies(["Segoe UI Variable Text", "Segoe UI", "Inter", "Noto Sans"])
    font.setPixelSize(14)
    app.setFont(font)


def stylesheet(accent: str) -> str:
    accent_hover = QColor(accent).lighter(115).name()
    accent_pressed = QColor(accent).darker(115).name()
    return f"""
QMainWindow, QWidget#root {{ background: {BG}; }}
QWidget {{ color: {TEXT}; font-family: {FONT_FAMILIES}; font-size: 14px; }}
QToolTip {{ background: {SECTION}; color: {TEXT}; border: 1px solid {BORDER};
    padding: 6px 8px; border-radius: 6px; }}

/* Header */
QFrame#header {{ background: {CARD}; border-bottom: 1px solid {BORDER}; }}
QLabel#appTitle {{ font-size: 19px; font-weight: 700; letter-spacing: 0.2px; }}
QLabel#appSubtitle {{ color: {MUTED}; font-size: 12px; }}
QLabel#versionPill {{ color: {MUTED}; background: {SECTION}; border: 1px solid {BORDER};
    border-radius: 9px; padding: 1px 8px; font-size: 11px; font-weight: 600; }}
QPushButton#accentDot {{ border-radius: 7px; border: 2px solid {CARD}; }}
QPushButton#accentDot:checked {{ border: 2px solid {TEXT}; }}
QPushButton#accentDot:hover {{ border: 2px solid {MUTED}; }}

/* Cards */
QFrame#card {{ background: {CARD}; border: 1px solid {BORDER}; border-radius: 12px; }}
QFrame#card QLabel, QFrame#heroCard QLabel, QFrame#tile QLabel {{ background: transparent; border: none; }}
QLabel#cardCaption {{ color: {MUTED}; font-size: 11px; font-weight: 700; letter-spacing: 1.2px; }}
QLabel#bodyText {{ color: {TEXT}; font-size: 14px; }}
QLabel#mutedText {{ color: {MUTED}; font-size: 12px; }}

/* Drop zone */
QFrame#dropZone {{ background: {SECTION}; border: 1px dashed #3a4457; border-radius: 10px; }}
QFrame#dropZone[active="true"] {{ border: 1px dashed {accent}; background: {rgba(accent, 0.08)}; }}
QLabel#dropTitle {{ font-size: 14px; font-weight: 600; }}
QLabel#dropHint {{ color: {FAINT}; font-size: 12px; }}
QFrame#card QLabel#fileChip {{ background: {rgba(accent, 0.14)}; color: {TEXT}; border: 1px solid {rgba(accent, 0.45)};
    border-radius: 10px; padding: 4px 12px; font-size: 13px; font-weight: 600; }}

/* Buttons */
QPushButton {{ background: {SECTION}; color: {TEXT}; border: 1px solid {BORDER};
    border-radius: 8px; padding: 7px 14px; font-weight: 600; }}
QPushButton:hover {{ background: #232b3a; border-color: #3a4457; }}
QPushButton:pressed {{ background: #1a202b; }}
QPushButton:focus {{ border-color: {accent}; }}
QPushButton:disabled {{ color: {FAINT}; background: {CARD}; border-color: {BORDER}; }}
QPushButton#primaryButton {{ background: {accent}; color: #0b0e13; border: none;
    font-size: 15px; font-weight: 700; padding: 10px 28px; }}
QPushButton#primaryButton:hover {{ background: {accent_hover}; }}
QPushButton#primaryButton:pressed {{ background: {accent_pressed}; }}
QPushButton#primaryButton:disabled {{ background: #26303f; color: {FAINT}; }}
QPushButton#secondaryButton {{ font-size: 14px; padding: 10px 18px; }}
QPushButton#ghostButton {{ background: transparent; border: 1px solid transparent; color: {MUTED};
    padding: 5px 10px; font-weight: 600; }}
QPushButton#ghostButton:hover {{ background: {SECTION}; color: {TEXT}; border-color: {BORDER}; }}
QPushButton#ghostButton:checked {{ background: {rgba(accent, 0.14)}; color: {TEXT}; border-color: {rgba(accent, 0.45)}; }}
QPushButton#ghostButton:disabled {{ color: #4f5869; }}
QPushButton#coffeeButton {{ background: transparent; border: none; padding: 0; }}

QCheckBox {{ color: {MUTED}; spacing: 8px; font-size: 13px; background: transparent; }}
QCheckBox:hover {{ color: {TEXT}; }}
QCheckBox::indicator {{ width: 16px; height: 16px; border-radius: 4px; border: 1px solid #4a5568; background: {SECTION}; }}
QCheckBox::indicator:checked {{ background: {accent}; border-color: {accent}; }}

/* Hero result */
QLabel#verdictText {{ font-size: 28px; font-weight: 800; letter-spacing: 0.6px; }}
QLabel#verdictSub {{ color: {MUTED}; font-size: 13px; }}
QLabel#scoreValue {{ font-size: 38px; font-weight: 800; }}
QLabel#scoreMax {{ color: {MUTED}; font-size: 16px; font-weight: 600; }}
QLabel#scoreCaption {{ color: {MUTED}; font-size: 11px; font-weight: 700; letter-spacing: 1px; }}
QProgressBar#riskBar {{ background: {SECTION}; border: none; border-radius: 3px; }}

/* Metric tiles */
QFrame#tile {{ background: {SECTION}; border: 1px solid {BORDER}; border-radius: 10px; }}
QLabel#tileLabel {{ color: {MUTED}; font-size: 11px; font-weight: 700; letter-spacing: 1px; }}
QLabel#tileValue {{ font-size: 15px; font-weight: 700; }}
QLabel#tileSub {{ color: {FAINT}; font-size: 11px; }}

/* Findings */
QTextBrowser#findingsView {{ background: transparent; border: none; font-size: 14px; }}

/* Tabs */
QTabWidget::pane {{ background: {CARD}; border: 1px solid {BORDER}; border-radius: 12px; top: -1px; }}
QTabBar {{ background: transparent; }}
QTabBar::tab {{ background: transparent; color: {MUTED}; padding: 9px 18px; margin-right: 4px;
    border: none; border-bottom: 2px solid transparent; font-weight: 600; font-size: 13px; }}
QTabBar::tab:hover {{ color: {TEXT}; background: {SECTION}; border-top-left-radius: 8px; border-top-right-radius: 8px; }}
QTabBar::tab:selected {{ color: {TEXT}; border-bottom: 2px solid {accent}; }}
QTabBar::tab:focus {{ color: {TEXT}; }}

QTextEdit, QListWidget, QTableWidget, QTextBrowser {{ background: {CARD}; color: {TEXT};
    border: none; selection-background-color: {rgba(accent, 0.35)}; selection-color: {TEXT}; }}
QTextEdit#techText {{ font-family: {MONO_FAMILIES}; font-size: 13px; padding: 10px; }}
QListWidget {{ padding: 6px; outline: none; }}
QListWidget::item {{ padding: 9px 10px; border-bottom: 1px solid {BORDER}; }}
QListWidget::item:hover {{ background: {SECTION}; }}
QListWidget::item:selected {{ background: {rgba(accent, 0.18)}; color: {TEXT}; }}
QTableWidget {{ gridline-color: {BORDER}; padding: 6px; }}
QTableWidget::item {{ padding: 6px 8px; }}
QHeaderView::section {{ background: {SECTION}; color: {MUTED}; border: none; border-bottom: 1px solid {BORDER};
    padding: 7px 8px; font-weight: 700; font-size: 12px; }}
QTableCornerButton::section {{ background: {SECTION}; border: none; }}

/* Technical log */
QFrame#logPanel {{ background: {CARD}; border: 1px solid {BORDER}; border-radius: 12px; }}
QTextEdit#logText {{ background: #0b0d11; color: #d8e2e8; font-family: {MONO_FAMILIES}; font-size: 12px;
    border: 1px solid {BORDER}; border-radius: 8px; padding: 8px; }}

/* Feedback bar */
QFrame#feedbackBar {{ background: {CARD}; border: 1px solid {BORDER}; border-radius: 10px; }}
QToolButton#feedbackToggle {{ background: transparent; border: none; color: {MUTED}; font-weight: 600;
    font-size: 13px; padding: 4px 6px; }}
QToolButton#feedbackToggle:hover {{ color: {TEXT}; }}
QRadioButton {{ background: {SECTION}; color: {MUTED}; border: 1px solid {BORDER}; border-radius: 10px;
    padding: 4px 12px; font-size: 12px; font-weight: 600; }}
QRadioButton:hover {{ color: {TEXT}; border-color: #3a4457; }}
QRadioButton:checked {{ color: {TEXT}; background: {rgba(accent, 0.16)}; border-color: {accent}; }}
QRadioButton::indicator {{ width: 0; height: 0; }}

/* Scrollbars */
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: #333c4d; border-radius: 4px; min-height: 28px; }}
QScrollBar::handle:vertical:hover {{ background: #46516a; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background: #333c4d; border-radius: 4px; min-width: 28px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}

/* Status bar */
QStatusBar {{ background: {CARD}; color: {MUTED}; border-top: 1px solid {BORDER}; font-size: 12px; }}
QStatusBar::item {{ border: none; }}
QStatusBar QLabel {{ color: {MUTED}; font-size: 12px; }}
QMenu {{ background: {SECTION}; border: 1px solid {BORDER}; padding: 4px; }}
QMenu::item {{ padding: 6px 18px; border-radius: 6px; }}
QMenu::item:selected {{ background: {rgba(accent, 0.25)}; }}
"""


def hero_style(level: str) -> str:
    """Card style of the result panel: tinted by the verdict, calm when nothing is analysed."""
    if level == "neutral":
        return f"QFrame#heroCard {{ background: {CARD}; border: 1px solid {BORDER}; border-radius: 12px; }}"
    color = LEVEL_COLORS[level]
    strength = 0.20 if level == "danger" else 0.15
    return (
        "QFrame#heroCard {"
        f"background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {rgba(color, strength)}, stop:0.65 {CARD});"
        f"border: 1px solid {rgba(color, 0.55)}; border-radius: 12px; }}"
    )


def _canvas(size: int) -> tuple[QPixmap, QPainter]:
    pixmap = QPixmap(size * 2, size * 2)
    pixmap.setDevicePixelRatio(2)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    return pixmap, painter


def _shield_path(size: float) -> QPainterPath:
    s = size / 100
    path = QPainterPath()
    path.moveTo(50 * s, 4 * s)
    path.lineTo(90 * s, 18 * s)
    path.cubicTo(90 * s, 58 * s, 76 * s, 82 * s, 50 * s, 96 * s)
    path.cubicTo(24 * s, 82 * s, 10 * s, 58 * s, 10 * s, 18 * s)
    path.closeSubpath()
    return path


def verdict_icon(level: str, size: int = 64) -> QPixmap:
    """Shield with a tick (safe), an exclamation mark (warning/danger) or a dash (no result)."""
    color = QColor(LEVEL_COLORS.get(level, FAINT))
    pixmap, p = _canvas(size)
    fill = QColor(color)
    fill.setAlphaF(0.18)
    p.setBrush(fill)
    p.setPen(QPen(color, size * 0.05))
    p.drawPath(_shield_path(size))
    s = size / 100
    pen = QPen(color, size * 0.085, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.NoBrush)
    if level == "ok":
        p.drawPolyline([QPointF(33 * s, 50 * s), QPointF(45 * s, 62 * s), QPointF(68 * s, 38 * s)])
    elif level in ("warning", "danger"):
        p.drawLine(QPointF(50 * s, 30 * s), QPointF(50 * s, 56 * s))
        p.setBrush(color)
        p.setPen(Qt.NoPen)
        p.drawEllipse(QPointF(50 * s, 70 * s), 5 * s, 5 * s)
    else:
        p.drawLine(QPointF(36 * s, 50 * s), QPointF(64 * s, 50 * s))
    p.end()
    return pixmap


def envelope_icon(color: str, size: int = 32) -> QPixmap:
    pixmap, p = _canvas(size)
    s = size / 100
    p.setPen(QPen(QColor(color), size * 0.07, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
    p.setBrush(Qt.NoBrush)
    p.drawRoundedRect(QRectF(10 * s, 24 * s, 80 * s, 56 * s), 8 * s, 8 * s)
    p.drawPolyline([QPointF(14 * s, 30 * s), QPointF(50 * s, 56 * s), QPointF(86 * s, 30 * s)])
    p.end()
    return pixmap


def dot_icon(level: str, size: int = 12) -> QPixmap:
    pixmap, p = _canvas(size)
    p.setPen(Qt.NoPen)
    p.setBrush(QColor(LEVEL_COLORS.get(level, FAINT)))
    p.drawEllipse(QRectF(size * 0.15, size * 0.15, size * 0.7, size * 0.7))
    p.end()
    return pixmap
