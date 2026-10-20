"""Help → About window.

Links open only when the user clicks them. A link whose URL is empty is
not shown, so an address goes live only once it is filled in below.
"""
from __future__ import annotations

import html

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFrame,
    QLabel,
    QVBoxLayout,
)

from . import __version__
from .gui_theme import INFO, MUTED
from .i18n import text

GITHUB_URL = "https://github.com/3en4all/PhishingInspector"

# (text key, URL). Empty URL = hidden until the address is confirmed.
PROJECT_LINKS = (
    ("about_link_site", "https://3en4all.github.io/"),
    ("about_link_ecosystem", ""),  # e.g. cuplink.to/3en4all, after it is checked
    ("about_link_github", GITHUB_URL),
    ("about_link_privacy", f"{GITHUB_URL}/blob/main/PRIVACY.md"),
)
COMMUNITY_LINKS = (
    ("about_link_facebook", "https://www.facebook.com/profile.php?id=61588740009580"),
    ("about_link_youtube", "https://www.youtube.com/@BlastArbiter"),
)
SUPPORT_URL = "https://buycoffee.to/3en4all"

ACCENT = INFO


def _links_html(language: str, links) -> str:
    items = [
        f'<a href="{html.escape(url)}" style="color:{ACCENT}; '
        f'text-decoration:none; font-weight:600;">'
        f"{html.escape(text(language, key))}</a>"
        for key, url in links
        if url
    ]
    return " &nbsp;•&nbsp; ".join(items)


def _section(layout: QVBoxLayout, title: str, body: str) -> None:
    if not body:
        return
    heading = QLabel(title)
    heading.setStyleSheet("font-size: 13px; font-weight: 700; margin-top: 6px;")
    layout.addWidget(heading)

    label = QLabel(body)
    label.setWordWrap(True)
    label.setTextFormat(Qt.RichText)
    label.setTextInteractionFlags(Qt.TextBrowserInteraction)
    label.setOpenExternalLinks(True)
    layout.addWidget(label)


class AboutDialog(QDialog):
    def __init__(self, parent=None, language: str = "pl") -> None:
        super().__init__(parent)
        t = lambda key, **values: text(language, key, **values)  # noqa: E731
        self.setWindowTitle(t("about_window_title"))
        self.setModal(True)
        self.setMinimumWidth(500)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 16)
        layout.setSpacing(8)

        name = QLabel("Phishing Inspector")
        name.setStyleSheet("font-size: 22px; font-weight: 800;")
        layout.addWidget(name)

        badges = QLabel(t("about_badges", version=__version__))
        badges.setStyleSheet(
            f"color: #0b0e13; background: {ACCENT}; border-radius: 9px; "
            "padding: 3px 10px; font-size: 11px; font-weight: 700;"
        )
        badges.setMaximumWidth(badges.sizeHint().width() + 4)
        layout.addWidget(badges)

        tagline = QLabel(t("about_tagline"))
        tagline.setStyleSheet(f"font-size: 13px; color: {MUTED}; margin-bottom: 4px;")
        layout.addWidget(tagline)

        description = QLabel(t("about_description"))
        description.setWordWrap(True)
        layout.addWidget(description)

        _section(layout, t("about_project_title"), _links_html(language, PROJECT_LINKS))
        _section(layout, t("about_community_title"), _links_html(language, COMMUNITY_LINKS))

        if SUPPORT_URL:
            support = (
                f"{html.escape(t('about_support_text'))}<br>"
                f'<a href="{html.escape(SUPPORT_URL)}" style="color:{ACCENT}; '
                f'text-decoration:none; font-weight:600;">'
                f"{html.escape(t('about_support_link'))}</a>"
            )
            _section(layout, t("about_support_title"), support)

        disclaimer = QLabel("⚠  " + t("about_disclaimer"))
        disclaimer.setWordWrap(True)
        disclaimer.setStyleSheet(
            "background: rgba(249,168,37,0.15); border: 1px solid #f9a825; "
            "border-radius: 6px; padding: 8px 10px; margin-top: 8px;"
        )
        layout.addWidget(disclaimer)

        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setStyleSheet("color: rgba(127,127,127,0.35);")
        layout.addWidget(line)

        footer = QLabel(t("about_footer"))
        footer.setStyleSheet(f"font-size: 11px; color: {MUTED};")
        layout.addWidget(footer)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.button(QDialogButtonBox.Close).setText(t("about_close"))
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def showEvent(self, event) -> None:
        # Wrapped labels get their final font from the parent's style sheet
        # only when polished; size the dialog after that so no text is cut.
        for widget in (self, *self.findChildren(QLabel)):
            widget.ensurePolished()
        layout = self.layout()
        if layout.hasHeightForWidth():
            self.resize(self.width(), layout.totalHeightForWidth(self.width()))
        super().showEvent(event)
