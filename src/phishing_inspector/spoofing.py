from __future__ import annotations

from dataclasses import dataclass, field
from email.message import Message

from .alignment import relaxed_align
from .brands import brand_named, brand_owning
from .domains import is_freemail, registrable_domain
from .domain_analysis import analyze_domain, extract_display_name, extract_email_domain


@dataclass(slots=True)
class SpoofingAnalysis:
    suspicious: bool
    reasons: list[str]
    from_domain: str | None
    reply_to_domain: str | None
    return_path_domain: str | None
    # Stable rule codes, one per reason that has a scoring rule.
    codes: list[str] = field(default_factory=list)
    display_name: str = ""
    claimed_brand: str | None = None


def _identity_mismatch(
    label: str,
    from_domain: str | None,
    other_domain: str | None,
) -> str | None:
    if not from_domain or not other_domain:
        return None

    aligned = relaxed_align(from_domain, other_domain)

    if aligned is False:
        return (
            f"From domain is not organizationally aligned with {label} domain: "
            f"{from_domain} != {other_domain}"
        )

    return None


def analyze_spoofing(message: Message) -> SpoofingAnalysis:
    from_header = message.get("From")
    from_domain = extract_email_domain(from_header)
    reply_to_domain = extract_email_domain(message.get("Reply-To"))
    return_path_domain = extract_email_domain(message.get("Return-Path"))
    display_name = extract_display_name(from_header)

    reasons: list[str] = []
    codes: list[str] = []

    reply_to_mismatch = _identity_mismatch(
        "Reply-To",
        from_domain,
        reply_to_domain,
    )
    if reply_to_mismatch:
        reasons.append(reply_to_mismatch)
        codes.append("SENDER_REPLY_TO_MISMATCH")

    if (
        reply_to_domain
        and is_freemail(reply_to_domain)
        and registrable_domain(reply_to_domain) != registrable_domain(from_domain or "")
    ):
        # Replies go to a free mailbox that is not the sender's address: the
        # usual set-up for CEO and invoice fraud. DMARC does not cover Reply-To.
        reasons.append(
            f"Replies go to a free mailbox ({reply_to_domain}) instead of the "
            f"sender's address ({from_domain or '(none)'})"
        )
        codes.append("SENDER_REPLY_TO_FREEMAIL")

    return_path_mismatch = _identity_mismatch(
        "Return-Path",
        from_domain,
        return_path_domain,
    )
    if return_path_mismatch:
        reasons.append(return_path_mismatch)
        codes.append("SENDER_RETURN_PATH_MISMATCH")

    for label, domain in (
        ("From", from_domain),
        ("Reply-To", reply_to_domain),
        ("Return-Path", return_path_domain),
    ):
        if not domain:
            continue

        finding = analyze_domain(domain)

        if finding.suspicious:
            for reason in finding.reasons:
                reasons.append(f"{label} domain: {reason}")
            for code in finding.codes or []:
                codes.append(f"SENDER_{code}")

    # "mBank S.A." <alert@mbank-weryfikacja.com>: the name people read names
    # a brand, the address does not belong to it.
    named = brand_named(display_name)
    claimed_brand: str | None = None

    if named is not None:
        claimed, disguised = named
        claimed_brand = claimed.name
        owner = brand_owning(from_domain) if from_domain else None

        if owner is None or owner.key != claimed.key:
            how = " with swapped letters" if disguised else ""
            reasons.append(
                f"Sender name claims to be {claimed.name}{how}, but the address domain "
                f"{from_domain or '(none)'} does not belong to {claimed.name}"
            )
            codes.append("SENDER_BRAND_NAME_SPOOF")

    return SpoofingAnalysis(
        suspicious=bool(reasons),
        reasons=reasons,
        from_domain=from_domain,
        reply_to_domain=reply_to_domain,
        return_path_domain=return_path_domain,
        codes=codes,
        display_name=display_name,
        claimed_brand=claimed_brand,
    )
