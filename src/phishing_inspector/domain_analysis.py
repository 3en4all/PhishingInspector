from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from email.utils import getaddresses, parseaddr

from .brands import BRAND_DOMAINS, brand_owning, imitated_brand
from .domains import DIGIT_SUBSTITUTIONS, decode_idna
from .domains import registrable_domain as _registrable_domain

# Kept for backwards compatibility with older imports.
COMMON_SUBSTITUTIONS = DIGIT_SUBSTITUTIONS


@dataclass(slots=True)
class DomainFinding:
    domain: str
    suspicious: bool
    reasons: list[str]
    closest_brand: str | None = None
    similarity: float | None = None
    codes: list[str] | None = None


def extract_email_domain(value: str | None) -> str | None:
    if not value:
        return None

    addresses = getaddresses([str(value)])
    address = addresses[0][1] if addresses else parseaddr(str(value))[1]

    if "@" not in address:
        return None

    domain = address.rsplit("@", 1)[1].strip().lower().rstrip(">").strip(".")
    return domain or None


def extract_display_name(value: str | None) -> str:
    if not value:
        return ""

    name, _ = parseaddr(str(value))
    return name.strip()


def registrable_domain(hostname: str) -> str:
    return _registrable_domain(hostname)


def _normalize_for_similarity(value: str) -> str:
    value = unicodedata.normalize("NFKC", decode_idna(value).lower())
    value = value.translate(COMMON_SUBSTITUTIONS)
    value = re.sub(r"[^a-z0-9.]", "", value)
    return value


def levenshtein_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    previous = list(range(len(b) + 1))

    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            insert_cost = current[j - 1] + 1
            delete_cost = previous[j] + 1
            replace_cost = previous[j - 1] + (ca != cb)
            current.append(min(insert_cost, delete_cost, replace_cost))
        previous = current

    return previous[-1]


def similarity_ratio(a: str, b: str) -> float:
    na = _normalize_for_similarity(a)
    nb = _normalize_for_similarity(b)

    max_len = max(len(na), len(nb))
    if max_len == 0:
        return 1.0

    distance = levenshtein_distance(na, nb)
    return 1.0 - (distance / max_len)


def analyze_domain(domain: str) -> DomainFinding:
    normalized = domain.lower().strip(".")
    reasons: list[str] = []
    codes: list[str] = []

    if normalized.startswith("xn--") or ".xn--" in normalized:
        reasons.append("Domain uses Punycode")
        codes.append("DOMAIN_PUNYCODE")

    if brand_owning(normalized) is not None:
        return DomainFinding(
            domain=normalized,
            suspicious=bool(reasons),
            reasons=reasons,
            codes=codes,
        )

    registered = _registrable_domain(normalized)
    closest_brand: str | None = None
    closest_similarity = 0.0

    # Whole-domain comparison against each brand's main domain. Short brand
    # names (ing.pl, pko.pl) are skipped here: one changed letter turns them
    # into unrelated real domains such as pkp.pl.
    for brand_domain in BRAND_DOMAINS:
        if len(brand_domain.split(".", 1)[0]) < 6:
            continue

        similarity = similarity_ratio(registered, brand_domain)
        if similarity > closest_similarity:
            closest_similarity = similarity
            closest_brand = brand_domain

    imitation = imitated_brand(normalized)

    if imitation is not None and imitation[1] == "lookalike":
        brand, _, similarity = imitation
        if similarity >= closest_similarity:
            closest_brand = brand.primary_domain
            closest_similarity = max(similarity, closest_similarity)

    if closest_brand and closest_similarity >= 0.82:
        reasons.append(
            f"Domain is visually similar to protected brand domain: "
            f"{closest_brand} ({closest_similarity:.0%})"
        )
        codes.append("DOMAIN_LOOKALIKE")
    elif imitation is not None and imitation[1] == "brand-name":
        brand = imitation[0]
        closest_brand = brand.primary_domain
        closest_similarity = imitation[2]
        reasons.append(
            f"Domain uses the brand name {brand.name} but does not belong to it: "
            f"{registered}"
        )
        codes.append("DOMAIN_BRAND_NAME")

    suspicious = bool(reasons)

    return DomainFinding(
        domain=normalized,
        suspicious=suspicious,
        reasons=reasons,
        closest_brand=closest_brand if suspicious else None,
        similarity=closest_similarity if suspicious else None,
        codes=codes,
    )
