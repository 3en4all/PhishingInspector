from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from .alignment import build_alignment
from .auth_analysis import parse_authentication_results
from .content_analysis import analyze_content
from .domain_analysis import extract_email_domain
from .eml_parser import (
    extract_and_analyze_attachments,
    extract_and_analyze_urls,
    extract_attachment_link_urls,
    extract_text,
)
from .header_analysis import analyze_headers
from .message_loader import load_message
from .models import EmailAnalysis
from .received_analysis import analyze_received_chain
from .scoring import score_analysis_detailed
from .spoofing import analyze_spoofing


def _dns_checks(from_domain: str | None, return_path_domain: str | None) -> dict:
    # Imported lazily: dnspython is optional and only needed here.
    from .dns_auth import check_dmarc_record, check_spf_record

    return {
        "enabled": True,
        "spf": check_spf_record(return_path_domain).to_dict() if return_path_domain else None,
        "dmarc": check_dmarc_record(from_domain).to_dict() if from_domain else None,
    }


def analyze_message(path: str | Path, *, network_checks: bool = False) -> EmailAnalysis:
    """Analyse an .eml or .msg file.

    Everything runs locally. ``network_checks=True`` additionally looks up the
    sender's SPF and DMARC DNS records; those queries go to DNS servers that
    the sender (possibly the attacker) may control, which can reveal that the
    message was opened. They are shown in the report and do not change the
    score.
    """
    source_path = Path(path).resolve()
    message = load_message(source_path)

    headers = analyze_headers(message)
    authentication = parse_authentication_results(message)
    received_chain = analyze_received_chain(message)
    spoofing = analyze_spoofing(message)

    from_domain = extract_email_domain(message.get("From"))
    return_path_domain = extract_email_domain(message.get("Return-Path"))

    sender_authenticated = (
        authentication.dmarc == "pass"
        and authentication.verified
        and not authentication.forged_pass_claim
    )

    urls = extract_and_analyze_urls(
        message,
        sender_domain=from_domain,
        sender_authenticated=sender_authenticated,
    )
    urls += extract_attachment_link_urls(
        message,
        sender_domain=from_domain,
        sender_authenticated=sender_authenticated,
    )
    attachments = extract_and_analyze_attachments(message)
    content = analyze_content(message.get("Subject"), extract_text(message))

    alignment = build_alignment(
        from_domain=from_domain,
        return_path_domain=return_path_domain,
        dkim_domain=authentication.dkim_domain,
    )

    if network_checks:
        dns_checks = _dns_checks(from_domain, return_path_domain)
    else:
        dns_checks = {"enabled": False, "spf": None, "dmarc": None}

    score, verdict, reasons, findings = score_analysis_detailed(
        headers=headers,
        urls=urls,
        attachments=attachments,
        authentication=authentication,
        spoofing=spoofing,
        received_chain=received_chain,
        content=content,
    )

    limitations: list[str] = []
    source_format = message.get("X-PhishingInspector-Source-Format")
    if source_format == "MSG":
        limitations.extend(message.get_all("X-PhishingInspector-Limitation", failobj=[]))

    result = EmailAnalysis(
        source_file=str(source_path),
        headers=headers,
        urls=urls,
        attachments=attachments,
        score=score,
        verdict=verdict,
        reasons=reasons,
        authentication=asdict(authentication),
        received_chain=asdict(received_chain),
        spoofing=asdict(spoofing),
        content=content.to_dict(),
        findings=findings,
        limitations=[str(item) for item in limitations],
    )

    result.authentication["alignment"] = alignment.to_dict()
    result.authentication["dns_checks"] = dns_checks

    return result


def analyze_eml(path: str | Path, *, network_checks: bool = False) -> EmailAnalysis:
    return analyze_message(path, network_checks=network_checks)
