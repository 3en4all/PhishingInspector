from __future__ import annotations

from email.message import EmailMessage
from pathlib import Path

from .eml_parser import load_eml


class UnsupportedMessageFormatError(ValueError):
    pass


def load_message(path: str | Path) -> EmailMessage:
    source = Path(path).resolve()
    suffix = source.suffix.lower()

    if suffix == ".eml":
        return load_eml(source)

    if suffix == ".msg":
        return load_msg(source)

    raise UnsupportedMessageFormatError(
        f"Unsupported message format: {suffix or '<none>'}"
    )


def load_msg(path: Path) -> EmailMessage:
    if not path.exists():
        raise FileNotFoundError(f"Email file does not exist: {path}")

    if not path.is_file():
        raise ValueError(f"Input path is not a file: {path}")

    try:
        import extract_msg  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "MSG support requires the optional package 'extract-msg'. "
            "Install it with: python -m pip install \"phishing-inspector[msg]\""
        ) from exc

    msg = extract_msg.Message(str(path))
    email_message = EmailMessage()

    # Outlook keeps the original transport headers (Received,
    # Authentication-Results, Return-Path, Reply-To) in the .msg file when the
    # message came from outside. Copy them so the header checks can run.
    transport = getattr(msg, "header", None)
    copied = False

    if transport is not None:
        try:
            items = list(transport.items())
        except Exception:
            items = []

        for name, value in items:
            if name.lower().startswith("content-") or name.lower() == "mime-version":
                continue
            try:
                email_message[name] = str(value)
                copied = True
            except Exception:
                continue

    if not copied:
        if msg.sender:
            email_message["From"] = msg.sender
        if msg.to:
            email_message["To"] = msg.to
        if msg.cc:
            email_message["Cc"] = msg.cc
        if msg.subject:
            email_message["Subject"] = msg.subject
        email_message["X-PhishingInspector-Limitation"] = (
            "The .msg file has no original mail headers; SPF/DKIM/DMARC, "
            "Received chain and Reply-To/Return-Path checks could not run"
        )

    email_message["X-PhishingInspector-Source-Format"] = "MSG"
    email_message.set_content(msg.body or "")

    html_body = getattr(msg, "htmlBody", None)
    if html_body:
        if isinstance(html_body, bytes):
            html_body = html_body.decode("utf-8", errors="replace")
        email_message.add_alternative(str(html_body), subtype="html")

    for attachment in msg.attachments:
        filename = (
            getattr(attachment, "longFilename", None)
            or getattr(attachment, "shortFilename", None)
            or "unnamed-attachment"
        )

        data = getattr(attachment, "data", None)
        if data is None:
            continue

        payload = (
            data.encode("utf-8", errors="replace")
            if isinstance(data, str)
            else bytes(data)
        )

        mimetype = getattr(attachment, "mimetype", None) or "application/octet-stream"
        maintype, _, subtype = str(mimetype).partition("/")

        # add_attachment() needs str for text/*; keep the bytes intact instead.
        if maintype == "text" or not subtype:
            maintype, subtype = "application", "octet-stream"

        email_message.add_attachment(
            payload,
            maintype=maintype or "application",
            subtype=subtype or "octet-stream",
            filename=filename,
        )

    return email_message
