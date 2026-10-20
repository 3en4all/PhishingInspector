from __future__ import annotations

import ipaddress
import re
import unicodedata
from functools import lru_cache

try:
    import tldextract  # type: ignore

    # Offline only: use the Public Suffix List snapshot bundled with the
    # package. No network fetch, no cache directory on the user's disk.
    _EXTRACT = tldextract.TLDExtract(
        suffix_list_urls=(),
        cache_dir=None,
        include_psl_private_domains=True,
    )
except Exception:  # pragma: no cover - exercised only without tldextract
    _EXTRACT = None


# Used only when tldextract is unavailable.
_FALLBACK_TWO_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk",
    "com.au", "net.au", "org.au",
    "co.jp", "ne.jp", "or.jp",
    "com.br", "com.pl", "net.pl", "org.pl", "info.pl", "biz.pl",
    "edu.pl", "gov.pl", "waw.pl", "github.io", "gitlab.io",
    "web.app", "firebaseapp.com", "pages.dev", "workers.dev",
    "blogspot.com", "herokuapp.com", "netlify.app", "vercel.app",
}

# TLDs that are cheap to register and heavily abused for phishing. A link to
# one of them is a risk signal, and a brand name on one is never trusted.
RISKY_TLDS = frozenset({
    "top", "xyz", "zip", "mov", "icu", "cfd", "sbs", "click", "cyou", "rest",
    "bond", "quest", "buzz", "lol", "monster", "beauty", "hair", "skin",
    "makeup", "boats", "autos", "mom", "cam", "tk", "ml", "ga", "cf", "gq",
    "work", "support", "live", "online", "site", "shop", "store", "fun",
    "loan", "win", "bid", "kim", "country", "stream", "download", "racing",
    "review", "trade", "party", "date", "faith", "science", "accountant",
})

# Free mailbox providers: anyone can open an address there in a minute.
FREEMAIL_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "msn.com", "yahoo.com", "ymail.com", "icloud.com", "me.com", "aol.com",
    "proton.me", "protonmail.com", "pm.me", "gmx.com", "gmx.net", "gmx.de",
    "mail.com", "zoho.com", "yandex.com", "yandex.ru", "mail.ru", "tutanota.com",
    "wp.pl", "o2.pl", "onet.pl", "op.pl", "interia.pl", "interia.eu", "poczta.fm",
    "gazeta.pl", "tlen.pl", "vp.pl", "onet.eu", "spoko.pl", "autograf.pl",
})


def is_freemail(domain: str | None) -> bool:
    return registrable_domain(domain) in FREEMAIL_DOMAINS if domain else False


# Cyrillic and Greek letters that look like Latin ones.
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y",
    "х": "x", "і": "i", "ј": "j", "ԁ": "d", "ɡ": "g", "ӏ": "l",
    "ѕ": "s", "һ": "h", "ԛ": "q", "ԝ": "w", "ο": "o", "α": "a",
    "ν": "v", "τ": "t", "ι": "i", "κ": "k", "ρ": "p",
})

DIGIT_SUBSTITUTIONS = str.maketrans({
    "0": "o",
    "1": "l",
    "3": "e",
    "5": "s",
    "7": "t",
    "@": "a",
})


def clean_host(hostname: str | None) -> str:
    return (hostname or "").strip().strip(".").lower()


def is_ip(hostname: str | None) -> bool:
    try:
        ipaddress.ip_address(clean_host(hostname).strip("[]"))
        return True
    except ValueError:
        return False


@lru_cache(maxsize=4096)
def registrable_domain(hostname: str | None) -> str:
    """Return the registrable domain (eTLD+1) using the Public Suffix List.

    ``a.b.allegro-pomoc.com.pl`` -> ``allegro-pomoc.com.pl``
    ``x.github.io`` -> ``x.github.io``
    """
    host = clean_host(hostname)

    if not host or is_ip(host):
        return host

    if _EXTRACT is not None:
        result = _EXTRACT(host)
        domain = getattr(result, "top_domain_under_public_suffix", None)
        if domain is None:
            domain = getattr(result, "registered_domain", "")
        if domain:
            return domain.lower()

    parts = [part for part in host.split(".") if part]

    if len(parts) <= 2:
        return ".".join(parts)

    for size in (3, 2):
        suffix = ".".join(parts[-(size - 1):])
        if suffix in _FALLBACK_TWO_LEVEL_SUFFIXES and len(parts) >= size:
            return ".".join(parts[-size:])

    return ".".join(parts[-2:])


def domain_label(hostname: str | None) -> str:
    """The registrable label without the public suffix (``mbank`` for ``mbank.pl``)."""
    registered = registrable_domain(hostname)
    return registered.split(".", 1)[0] if registered else ""


def public_suffix(hostname: str | None) -> str:
    registered = registrable_domain(hostname)
    return registered.split(".", 1)[1] if "." in registered else ""


def subdomain_part(hostname: str | None) -> str:
    host = clean_host(hostname)
    registered = registrable_domain(host)

    if not registered or host == registered:
        return ""

    return host[: -len(registered)].rstrip(".")


def same_organization(a: str | None, b: str | None) -> bool | None:
    if not a or not b:
        return None

    return registrable_domain(a) == registrable_domain(b)


def decode_idna(hostname: str) -> str:
    labels = []

    for label in clean_host(hostname).split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except (UnicodeError, ValueError):
                pass
        labels.append(label)

    return ".".join(labels)


def skeleton(value: str) -> str:
    """Map a domain or label to a comparable ASCII skeleton (homoglyphs, 0->o, ...)."""
    value = unicodedata.normalize("NFKC", decode_idna(value).lower())
    value = value.translate(_CONFUSABLES)
    value = unicodedata.normalize("NFKD", value)
    value = "".join(ch for ch in value if not unicodedata.combining(ch))
    value = value.translate(DIGIT_SUBSTITUTIONS)
    return re.sub(r"[^a-z0-9.\-]", "", value)
