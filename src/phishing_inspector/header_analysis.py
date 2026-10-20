from __future__ import annotations

from email.message import Message
from email.utils import parseaddr

from .models import HeaderAnalysis


def _extract_domain(address_header: str | None) -> str | None:
    if not address_header:
        return None

    _, address = parseaddr(address_header)

    if "@" not in address:
        return None

    domain = address.rsplit("@", 1)[1].strip().lower().rstrip(">")
    return domain or None


def analyze_headers(message: Message) -> HeaderAnalysis:
    from_header = message.get("From")
    reply_to = message.get("Reply-To")
    return_path = message.get("Return-Path")

    warnings: list[str] = []

    from_domain = _extract_domain(from_header)
    reply_to_domain = _extract_domain(reply_to)
    return_path_domain = _extract_domain(return_path)

    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        warnings.append(
            f"From domain differs from Reply-To domain: {from_domain} != {reply_to_domain}"
        )

    if from_domain and return_path_domain and from_domain != return_path_domain:
        warnings.append(
            f"From domain differs from Return-Path domain: {from_domain} != {return_path_domain}"
        )

    authentication_results = message.get_all("Authentication-Results", failobj=[])
    received_headers = message.get_all("Received", failobj=[])

    if not received_headers:
        warnings.append("Message does not contain any Received headers")

    if not message.get("Message-ID"):
        warnings.append("Message-ID header is missing")

    return HeaderAnalysis(
        from_header=from_header,
        reply_to=reply_to,
        return_path=return_path,
        subject=message.get("Subject"),
        message_id=message.get("Message-ID"),
        authentication_results=list(authentication_results),
        received_headers=list(received_headers),
        warnings=warnings,
    )
