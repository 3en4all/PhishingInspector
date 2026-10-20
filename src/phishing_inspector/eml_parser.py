from __future__ import annotations

from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path

from .attachment_analysis import analyze_attachment, extract_attachment_urls
from .html_links import scan_html
from .models import AttachmentInfo, UrlInfo
from .url_analysis import analyze_url, extract_urls

MAX_URLS = 500


def load_eml(path: Path) -> EmailMessage:
    if not path.exists():
        raise FileNotFoundError(f"Email file does not exist: {path}")

    if not path.is_file():
        raise ValueError(f"Input path is not a file: {path}")

    if path.suffix.lower() != ".eml":
        raise ValueError(f"Unsupported file extension: {path.suffix}")

    with path.open("rb") as handle:
        message = BytesParser(policy=policy.default).parse(handle)

    if not isinstance(message, EmailMessage):
        raise TypeError("Parsed object is not an EmailMessage")

    return message


def _text_parts(message: EmailMessage) -> list[tuple[str, str]]:
    """(content_type, text) of the readable body parts."""
    parts: list[tuple[str, str]] = []

    iterable = message.walk() if message.is_multipart() else [message]

    for part in iterable:
        if part.is_multipart():
            continue

        if part.get_content_disposition() == "attachment":
            continue

        content_type = part.get_content_type()

        if content_type not in {"text/plain", "text/html"}:
            continue

        try:
            content = part.get_content()
        except Exception:
            try:
                payload = part.get_payload(decode=True) or b""
                content = payload.decode("utf-8", errors="replace")
            except Exception:
                continue

        if isinstance(content, str):
            parts.append((content_type, content))

    return parts


def extract_text(message: EmailMessage) -> str:
    return "\n".join(text for _, text in _text_parts(message))


def extract_and_analyze_urls(
    message: EmailMessage,
    *,
    sender_domain: str | None = None,
    sender_authenticated: bool = False,
) -> list[UrlInfo]:
    results: list[UrlInfo] = []
    seen: set[tuple[str, str | None]] = set()

    def add(url: str, text: str | None, source: str) -> None:
        key = (url, text or None)
        if key in seen or len(results) >= MAX_URLS:
            return
        seen.add(key)
        results.append(
            analyze_url(
                url,
                text or None,
                source=source,
                sender_domain=sender_domain,
                sender_authenticated=sender_authenticated,
            )
        )

    parts = _text_parts(message)
    linked: set[str] = set()

    for content_type, text in parts:
        if content_type != "text/html":
            continue

        for link in scan_html(text).links:
            href = link.href
            scheme = href.split(":", 1)[0].lower() if ":" in href else ""
            if scheme in {"http", "https", "javascript", "data", "vbscript"}:
                linked.add(href)
                add(href, link.text, "html-form" if link.kind == "form" else "html-link")

    for _, text in parts:
        for url in extract_urls(text):
            if url not in linked and not any(url == r.url for r in results):
                add(url, None, "body")

    return results


def extract_and_analyze_attachments(message: EmailMessage) -> list[AttachmentInfo]:
    attachments: list[AttachmentInfo] = []

    for part in message.iter_attachments():
        payload = part.get_payload(decode=True)

        if payload is None:
            payload = b""

        attachments.append(
            analyze_attachment(
                filename=part.get_filename(),
                content_type=part.get_content_type(),
                payload=payload,
            )
        )

    return attachments


def extract_attachment_link_urls(
    message: EmailMessage,
    *,
    sender_domain: str | None = None,
    sender_authenticated: bool = False,
) -> list[UrlInfo]:
    results: list[UrlInfo] = []

    for part in message.iter_attachments():
        payload = part.get_payload(decode=True) or b""
        filename = part.get_filename() or "unnamed-attachment"

        for url, text in extract_attachment_urls(filename, part.get_content_type(), payload):
            if len(results) >= MAX_URLS:
                break
            scheme = url.split(":", 1)[0].lower() if ":" in url else ""
            if scheme not in {"http", "https", "javascript", "data", "vbscript"}:
                continue
            results.append(
                analyze_url(
                    url,
                    text or None,
                    source=f"attachment:{filename}",
                    sender_domain=sender_domain,
                    sender_authenticated=sender_authenticated,
                )
            )

    return results
