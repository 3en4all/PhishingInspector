from __future__ import annotations

from typing import Any

from .models import AttachmentInfo, Finding, HeaderAnalysis, UrlInfo

SUSPICIOUS_THRESHOLD = 20
DANGEROUS_THRESHOLD = 50

AUTH_WEIGHTS = {
    "spf": {"fail": 20, "softfail": 10, "temperror": 5, "permerror": 8},
    "dkim": {"fail": 20, "temperror": 5, "permerror": 8},
    "dmarc": {"fail": 25, "temperror": 5, "permerror": 8},
}

# Points for the strongest rule hit by each attachment.
ATTACHMENT_POINTS = {
    "ATTACHMENT_EXECUTABLE": (50, "Dangerous attachment"),
    "ATTACHMENT_DOUBLE_EXTENSION": (50, "Dangerous attachment"),
    "ATTACHMENT_HTML_ACTIVE": (50, "Web page attachment with a form or script"),
    "ATTACHMENT_MACRO": (35, "Macro-enabled attachment"),
    "ATTACHMENT_HTML": (30, "Web page / SVG attachment"),
    "ATTACHMENT_DISK_IMAGE": (30, "Disk image attachment"),
    "ATTACHMENT_PDF_ACTIVE": (30, "PDF with active content"),
    "ATTACHMENT_ENCRYPTED_ARCHIVE": (25, "Password-protected archive"),
}

# Strong link rules count once per message, on top of the per-URL score.
URL_RULE_POINTS = {
    "URL_TEXT_MISMATCH": (30, "Link text shows a different site than the link opens"),
    "URL_BRAND_IMITATION": (30, "Link domain imitates a known brand"),
    "URL_BRAND_SUBDOMAIN": (25, "Link puts a brand name in front of someone else's domain"),
    "URL_IP_HOST": (20, "Link points to a bare IP address instead of a domain"),
    "URL_SCRIPT_SCHEME": (20, "Link uses a javascript:/data: scheme"),
    "URL_REDIRECT_TO_SUSPICIOUS": (15, "Link redirects to a suspicious address"),
}

BRAND_NAME_SPOOF_POINTS = 40
FORGED_AUTH_POINTS = 20
MISSING_AUTH_POINTS = 10
REPLY_TO_FREEMAIL_POINTS = 10
QR_LURE_POINTS = 20
SUBJECT_BRAND_POINTS = 20
PUNYCODE_SENDER_POINTS = 10


def _reason_codes(reasons: list[str]) -> list[str]:
    """Rule codes for spoofing objects that only carry text (older callers)."""
    codes: list[str] = []

    for reason in reasons:
        lower = reason.lower()
        if "not organizationally aligned" in lower or "differs from" in lower:
            codes.append("SENDER_MISMATCH")
        elif "visually similar" in lower:
            codes.append("SENDER_DOMAIN_LOOKALIKE")
        elif "does not belong to it" in lower:
            codes.append("SENDER_DOMAIN_BRAND_NAME")
        elif "sender name claims" in lower:
            codes.append("SENDER_BRAND_NAME_SPOOF")
        elif "punycode" in lower:
            codes.append("SENDER_DOMAIN_PUNYCODE")

    return codes


def _attachment_codes(attachment: AttachmentInfo) -> list[str]:
    codes = list(getattr(attachment, "rule_codes", None) or [])

    if codes:
        return codes

    lowered = " ".join(attachment.reasons).lower()
    if "executable" in lowered or "script" in lowered:
        return ["ATTACHMENT_EXECUTABLE"]
    if "macro-enabled" in lowered:
        return ["ATTACHMENT_MACRO"]
    return []


def score_analysis_detailed(
    headers: HeaderAnalysis | Any,
    urls: list[UrlInfo],
    attachments: list[AttachmentInfo],
    authentication: Any | None = None,
    spoofing: Any | None = None,
    received_chain: Any | None = None,
    content: Any | None = None,
    subject_brand: str | None = None,
) -> tuple[int, str, list[str], list[Finding]]:
    findings: list[Finding] = []
    context: list[str] = []

    def hit(code: str, points: int, message: str) -> None:
        findings.append(Finding(code=code, points=points, message=message))

    results = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}
    auth_trusted = True

    if authentication is not None:
        for mechanism in results:
            results[mechanism] = getattr(authentication, mechanism, "unknown") or "unknown"

        auth_trusted = bool(getattr(authentication, "verified", True)) and not bool(
            getattr(authentication, "forged_pass_claim", False)
        )

        if getattr(authentication, "forged_pass_claim", False):
            hit(
                "AUTH_FORGED_RESULTS",
                FORGED_AUTH_POINTS,
                "Forged authentication header: another server's Authentication-Results "
                "claims a pass the receiving server did not confirm",
            )
        elif not getattr(authentication, "verified", True):
            context.append(
                "Authentication-Results could not be tied to the receiving server; "
                "passes are not used to lower the risk"
            )

        for mechanism in ("spf", "dkim", "dmarc"):
            result = results[mechanism]
            points = AUTH_WEIGHTS.get(mechanism, {}).get(result, 0)

            # DMARC PASS confirms an aligned authentication path. DKIM FAIL
            # remains visible as context, but does not score by itself.
            if (
                mechanism == "dkim"
                and result == "fail"
                and results["dmarc"] == "pass"
                and auth_trusted
            ):
                context.append(
                    "DKIM result: fail, but DMARC passed; "
                    "treated as authentication context only"
                )
                continue

            if points:
                hit(f"AUTH_{mechanism.upper()}_{result.upper()}", points,
                    f"{mechanism.upper()} result: {result}")

    auth_pass_count = 0
    dmarc_pass = False
    if authentication is not None and auth_trusted:
        auth_pass_count = sum(1 for value in results.values() if value == "pass")
        dmarc_pass = results["dmarc"] == "pass"

    impersonation = False

    if spoofing is not None:
        codes = list(getattr(spoofing, "codes", None) or _reason_codes(spoofing.reasons))
        mismatch_count = sum(
            1 for code in codes
            if code in {"SENDER_MISMATCH", "SENDER_REPLY_TO_MISMATCH", "SENDER_RETURN_PATH_MISMATCH"}
        )

        if mismatch_count:
            # A DMARC pass is strong evidence that at least one authentication
            # path aligned with the visible From domain. Likewise, two or more
            # authentication passes make a third-party bounce/ESP domain a
            # common legitimate pattern rather than a phishing signal.
            if dmarc_pass or auth_pass_count >= 2:
                context.append(
                    "Sender identity differs across technical mail domains, "
                    "but strong authentication passed; treated as context only"
                )
            elif auth_pass_count == 1:
                hit("SENDER_MISMATCH", min(20, mismatch_count * 10),
                    "Sender identity alignment mismatch with limited authentication support")
            else:
                hit("SENDER_MISMATCH", min(30, mismatch_count * 15),
                    "Sender identity alignment mismatch detected")

        if "SENDER_REPLY_TO_FREEMAIL" in codes:
            hit("SENDER_REPLY_TO_FREEMAIL", REPLY_TO_FREEMAIL_POINTS,
                "Replies go to a free mailbox instead of the sender's address")

        lookalike_count = sum(
            1 for code in codes
            if code in {"SENDER_DOMAIN_LOOKALIKE", "SENDER_DOMAIN_BRAND_NAME"}
        )

        if lookalike_count:
            impersonation = True
            hit("SENDER_LOOKALIKE", min(35, 25 + (lookalike_count - 1) * 5),
                "Lookalike or impersonation domain detected")

        if "SENDER_BRAND_NAME_SPOOF" in codes:
            impersonation = True
            brand = getattr(spoofing, "claimed_brand", None) or "a known brand"
            hit("SENDER_BRAND_NAME_SPOOF", BRAND_NAME_SPOOF_POINTS,
                f"Sender name impersonates {brand} from a domain that does not belong to it")

        if "SENDER_DOMAIN_PUNYCODE" in codes:
            hit("SENDER_PUNYCODE", PUNYCODE_SENDER_POINTS, "Sender domain uses Punycode")

    suspicious_urls = [item for item in urls if item.suspicious]
    if suspicious_urls:
        url_score = min(30, 10 + (len(suspicious_urls) - 1) * 5)
        hit("URL_SUSPICIOUS", url_score,
            f"Suspicious URL indicators detected in {len(suspicious_urls)} URL(s)")

    url_codes = {code for item in urls for code in (getattr(item, "rule_codes", None) or [])}
    for code, (points, message) in URL_RULE_POINTS.items():
        if code in url_codes:
            hit(code, points, message)
            if code in {"URL_BRAND_IMITATION", "URL_BRAND_SUBDOMAIN"}:
                impersonation = True

    if (
        authentication is not None
        and impersonation
        and all(value in {"unknown", "none"} for value in results.values())
    ):
        hit("AUTH_MISSING", MISSING_AUTH_POINTS,
            "No SPF, DKIM or DMARC confirmation for a message that uses a brand")

    for attachment in attachments:
        codes = _attachment_codes(attachment)
        best = max(
            (ATTACHMENT_POINTS[code] for code in codes if code in ATTACHMENT_POINTS),
            default=None,
            key=lambda item: item[0],
        )

        if best is not None:
            points, label = best
            code = next(c for c in codes if ATTACHMENT_POINTS.get(c) == best)
            hit(code, points, f"{label}: {attachment.filename}")
        elif attachment.suspicious:
            hit("ATTACHMENT_SUSPICIOUS", 15, f"Suspicious attachment: {attachment.filename}")

    if content is not None and getattr(content, "points", 0):
        names = ", ".join(sorted(content.categories))
        hit("CONTENT_LURE", content.points, f"Message text uses phishing pressure: {names}")

    categories = set(getattr(content, "categories", None) or ()) if content is not None else set()
    if subject_brand and "credentials" in categories:
        hit("CONTENT_BRAND_MISMATCH", SUBJECT_BRAND_POINTS,
            f"Message about {subject_brand} asks for login details, but neither the "
            f"sender nor the links belong to {subject_brand}")

    if "qr_code" in categories and len(categories) >= 2:
        hit("CONTENT_QR_LURE", QR_LURE_POINTS,
            "Message asks to scan a QR code under pressure (link hidden in an image)")

    if received_chain is not None:
        for warning in received_chain.warnings:
            hit("RECEIVED_CHAIN", 5, f"Delivery-chain anomaly: {warning}")

    score = min(sum(f.points for f in findings), 100)

    if score >= DANGEROUS_THRESHOLD:
        verdict = "DANGEROUS"
    elif score >= SUSPICIOUS_THRESHOLD:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    reasons = [f"+{f.points} {f.message}" for f in findings] + context

    if not reasons:
        reasons.append("No currently implemented high-risk indicators detected")

    return score, verdict, reasons, findings


def score_analysis(
    headers: HeaderAnalysis | Any,
    urls: list[UrlInfo],
    attachments: list[AttachmentInfo],
    authentication: Any | None = None,
    spoofing: Any | None = None,
    received_chain: Any | None = None,
    content: Any | None = None,
) -> tuple[int, str, list[str]]:
    score, verdict, reasons, _ = score_analysis_detailed(
        headers=headers,
        urls=urls,
        attachments=attachments,
        authentication=authentication,
        spoofing=spoofing,
        received_chain=received_chain,
        content=content,
    )
    return score, verdict, reasons
