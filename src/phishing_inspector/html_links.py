from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser


@dataclass(slots=True)
class HtmlLink:
    href: str
    text: str
    kind: str  # "a" or "form"


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[HtmlLink] = []
        self.has_password_field = False
        self.has_script = False
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name.lower(): (value or "") for name, value in attrs}
        tag = tag.lower()

        if tag == "a" and values.get("href"):
            self._close_anchor()
            self._href = values["href"].strip()
            self._text = []
        elif tag == "form" and values.get("action"):
            self.links.append(HtmlLink(values["action"].strip(), "", "form"))
        elif tag == "input" and values.get("type", "").lower() == "password":
            self.has_password_field = True
        elif tag == "script":
            self.has_script = True
        elif tag in {"area"} and values.get("href"):
            self.links.append(HtmlLink(values["href"].strip(), values.get("alt", ""), "a"))

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a":
            self._close_anchor()

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def _close_anchor(self) -> None:
        if self._href is not None:
            text = " ".join("".join(self._text).split())
            self.links.append(HtmlLink(self._href, text, "a"))
        self._href = None
        self._text = []

    def close(self) -> None:
        super().close()
        self._close_anchor()


@dataclass(slots=True)
class HtmlScan:
    links: list[HtmlLink]
    has_password_field: bool
    has_script: bool


def scan_html(html: str) -> HtmlScan:
    parser = _LinkParser()

    try:
        parser.feed(html)
        parser.close()
    except Exception:
        pass

    return HtmlScan(
        links=parser.links,
        has_password_field=parser.has_password_field,
        has_script=parser.has_script,
    )
