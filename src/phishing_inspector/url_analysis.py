from __future__ import annotations

import ipaddress
import re
from urllib.parse import parse_qsl, unquote, urlsplit, urlunsplit

from .brands import BRANDS, brand_owning, imitated_brand
from .domains import RISKY_TLDS, is_ip, registrable_domain, subdomain_part
from .models import UrlInfo


URL_PATTERN = re.compile(r"(?ix)\b(https?://[^\s<>\"'()]+)")
_EMBEDDED_URL = re.compile(r"https?(?::|%3a)(?://|%2f%2f)[^\s&\"'<>]+", re.I)
_TEXT_DOMAIN = re.compile(
    r"^(?:https?://)?((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62})(?:[/:?#].*)?$",
    re.I,
)

SUSPICIOUS_TERMS = {
    "login", "signin", "verify", "verification", "account",
    "password", "secure", "update", "bank", "wallet", "invoice",
    "confirm", "credential", "auth",
    # Polish
    "logowanie", "zaloguj", "weryfikacja", "potwierdz", "haslo",
    "doplata", "platnosc", "faktura", "konto", "odblokuj", "zwrot",
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "t.ly", "rb.gy", "s.id",
    "tiny.cc", "lnkd.in", "qrco.de", "bit.do", "urlz.fr",
}

# Hosts where anyone can publish a page or a file. They belong to trusted
# companies, so a phishing page there inherits a clean-looking domain.
USER_CONTENT_HOSTS = {
    "sites.google.com", "docs.google.com", "drive.google.com", "forms.gle",
    "storage.googleapis.com", "firebasestorage.googleapis.com",
    "script.google.com", "forms.office.com", "1drv.ms", "onedrive.live.com",
    "dl.dropboxusercontent.com", "ipfs.io",
}
USER_CONTENT_SUFFIXES = (
    ".sharepoint.com", ".blob.core.windows.net", ".web.core.windows.net",
    ".r2.dev", ".pages.dev", ".workers.dev", ".github.io", ".netlify.app",
    ".vercel.app", ".web.app", ".firebaseapp.com", ".weebly.com",
    ".wixsite.com", ".webflow.io", ".glitch.me", ".repl.co",
    ".blogspot.com", ".000webhostapp.com", ".ngrok.io", ".ngrok-free.app",
    ".trycloudflare.com", ".surge.sh", ".onmicrosoft.com",
)

SCRIPT_SCHEMES = {"javascript", "data", "vbscript"}

# Kept for compatibility: the organizations treated as trusted for lure terms.
TRUSTED_ORGANIZATIONAL_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "paypal.com", "amazon.com",
    "facebook.com", "linkedin.com", "allegro.pl",
}

_SUBDOMAIN_BRAND_TOKENS = sorted(
    {token for brand in BRANDS for token in (brand.key, *brand.tokens) if len(token) >= 5}
)
# Product names companies use for their own servers (outlook.firma.pl).
_OWN_SERVICE_WORDS = ("outlook", "office365", "sharepoint", "onedrive")
# Short names (olx, ing, pko, dpd) only count as a whole subdomain label:
# olx.bezpieczna-platnosc.pl, but not polx.example.com.
_SUBDOMAIN_BRAND_LABELS = frozenset(
    token for brand in BRANDS for token in (brand.key, *brand.tokens) if len(token) >= 3
)


def extract_urls(text: str) -> list[str]:
    urls: list[str] = []

    for match in URL_PATTERN.finditer(text):
        url = match.group(1).rstrip(".,;:!?]}")

        if url not in urls:
            urls.append(url)

    return urls


def normalize_url(url: str) -> str:
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname.lower() if parsed.hostname else ""
    port = parsed.port
    netloc = hostname

    if port is not None and not (
        (scheme == "http" and port == 80)
        or (scheme == "https" and port == 443)
    ):
        netloc = f"{hostname}:{port}"

    return urlunsplit(
        (scheme, netloc, unquote(parsed.path or "/"), parsed.query, "")
    )


def _hostname_is_ip(hostname: str) -> bool:
    return is_ip(hostname)


_LOCAL_NETWORKS = tuple(ipaddress.ip_network(net) for net in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
    "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
))


def _is_private_ip(hostname: str) -> bool:
    try:
        address = ipaddress.ip_address(hostname.strip("[]"))
    except ValueError:
        return False
    # RFC 1918 / loopback / link-local only; documentation ranges such as
    # 203.0.113.0/24 are treated as public.
    return any(address in network for network in _LOCAL_NETWORKS)


def _organizational_domain(hostname: str) -> str:
    return registrable_domain(hostname)


def is_user_content_host(hostname: str) -> bool:
    host = hostname.lower().strip(".")
    return host in USER_CONTENT_HOSTS or host.endswith(USER_CONTENT_SUFFIXES)


def _is_trusted_domain(hostname: str) -> bool:
    if is_user_content_host(hostname):
        return False

    return (
        brand_owning(hostname) is not None
        or _organizational_domain(hostname) in TRUSTED_ORGANIZATIONAL_DOMAINS
    )


def _looks_like_brand_in_subdomain(hostname: str) -> bool:
    subdomain = subdomain_part(hostname)

    if not subdomain:
        labels = hostname.split(".")
        if len(labels) < 3:
            return False
        subdomain = ".".join(labels[:-2])

    if any(token in subdomain for token in _SUBDOMAIN_BRAND_TOKENS):
        return True

    labels = re.split(r"[.\-_]", subdomain)
    return any(label in _SUBDOMAIN_BRAND_LABELS for label in labels)


def domain_shown_in_text(text: str | None) -> str | None:
    """The domain a link's visible text shows, if the text looks like a URL."""
    if not text:
        return None

    candidate = text.strip().strip("<>[]()\"'").lower()

    if " " in candidate or len(candidate) > 200:
        return None

    match = _TEXT_DOMAIN.match(candidate)
    if not match:
        return None

    domain = match.group(1)
    tld = domain.rsplit(".", 1)[-1]

    # "plik.pdf" or "index.html" is a file name, not a domain.
    if tld in {"pdf", "doc", "docx", "xls", "xlsx", "html", "htm", "jpg", "png", "zip", "txt"}:
        return None

    return domain


def _text_mismatch_reason(
    hostname: str,
    link_text: str | None,
    sender_domain: str | None,
    sender_authenticated: bool,
) -> tuple[str, bool] | None:
    """(reason, strong) when the link text shows a different site than the target."""
    shown = domain_shown_in_text(link_text)

    if not shown:
        return None

    if registrable_domain(shown) == registrable_domain(hostname):
        return None

    shown_brand = brand_owning(shown)
    target_brand = brand_owning(hostname)

    if shown_brand is not None and shown_brand == target_brand:
        return None

    reason = f"Link text shows {shown} but the link opens {hostname}"

    if shown_brand is None and sender_domain and sender_authenticated:
        # Newsletters often show their own address and send the click through
        # a tracking service. Context only when the authenticated sender owns
        # the shown domain.
        if registrable_domain(sender_domain) == registrable_domain(shown):
            return reason + " (sender's own domain via a tracking link; context only)", False

    return reason, True


def _embedded_urls(parsed) -> list[str]:
    found: list[str] = []
    haystacks = [parsed.path or ""]
    haystacks += [value for _, value in parse_qsl(parsed.query, keep_blank_values=True)]

    for haystack in haystacks:
        for match in _EMBEDDED_URL.finditer(unquote(haystack)):
            url = match.group(0)
            if url not in found:
                found.append(url)

    return found


def analyze_url(
    url: str,
    link_text: str | None = None,
    *,
    source: str = "body",
    sender_domain: str | None = None,
    sender_authenticated: bool = False,
    _depth: int = 0,
) -> UrlInfo:
    reasons: list[str] = []
    codes: list[str] = []
    context: list[str] = []

    def add(code: str, reason: str) -> None:
        codes.append(code)
        reasons.append(reason)

    scheme = url.split(":", 1)[0].strip().lower() if ":" in url else ""

    if scheme in SCRIPT_SCHEMES:
        return UrlInfo(
            url=url[:200],
            hostname=None,
            suspicious=True,
            reasons=[f"Link uses the {scheme}: scheme, which can run code or hide a page"],
            rule_codes=["URL_SCRIPT_SCHEME"],
            link_text=link_text,
            source=source,
        )

    try:
        original_parsed = urlsplit(url)
        normalized = normalize_url(url)
        parsed = urlsplit(normalized)
        hostname = (
            parsed.hostname.lower()
            if parsed.hostname
            else None
        )
    except ValueError:
        return UrlInfo(
            url=url,
            hostname=None,
            suspicious=True,
            reasons=["Malformed URL"],
            rule_codes=["URL_MALFORMED"],
            link_text=link_text,
            source=source,
        )

    if not hostname:
        return UrlInfo(
            url=url,
            hostname=None,
            suspicious=True,
            reasons=["URL does not contain a valid hostname"],
            rule_codes=["URL_MALFORMED"],
            link_text=link_text,
            source=source,
        )

    trusted_domain = _is_trusted_domain(hostname)

    if _hostname_is_ip(hostname):
        if _is_private_ip(hostname):
            # Printer or router panels in internal mail; phishing pages need a
            # public address.
            context.append("URL uses a local network IP address")
        else:
            add("URL_IP_HOST", "URL uses an IP address instead of a domain name")

    if hostname.startswith("xn--") or ".xn--" in hostname:
        add("URL_PUNYCODE", "URL contains an internationalized Punycode domain")

    if hostname in SHORTENER_DOMAINS:
        add("URL_SHORTENER", "URL uses a known URL shortening service")

    if "@" in original_parsed.netloc:
        add("URL_USERINFO", "URL contains user-info syntax using @")

    if len(hostname) > 60 and not trusted_domain:
        add("URL_LONG_HOST", "Hostname is unusually long")

    if _looks_like_brand_in_subdomain(hostname) and not trusted_domain:
        own_site = bool(
            sender_domain
            and sender_authenticated
            and registrable_domain(sender_domain) == registrable_domain(hostname)
            and any(word in subdomain_part(hostname) for word in _OWN_SERVICE_WORDS)
        )
        if own_site:
            # outlook.firma.pl linked from an authenticated firma.pl sender is
            # the company's own webmail, not an imitation. Bank and shop names
            # (olx.platnosc24.pl) are flagged even on the sender's own domain.
            context.append("Hostname contains a brand-like term on the sender's own domain")
        else:
            add("URL_BRAND_SUBDOMAIN", "Hostname contains a brand-like term in a subdomain")

    if not _hostname_is_ip(hostname):
        imitation = imitated_brand(hostname)
        if imitation is not None:
            brand, kind, similarity = imitation
            if kind == "lookalike":
                add(
                    "URL_BRAND_IMITATION",
                    f"Link domain imitates {brand.name}: {registrable_domain(hostname)} "
                    f"looks like {brand.primary_domain} ({similarity:.0%})",
                )
            else:
                add(
                    "URL_BRAND_IMITATION",
                    f"Link domain uses the brand name {brand.name} but does not belong "
                    f"to it: {registrable_domain(hostname)}",
                )

        tld = hostname.rsplit(".", 1)[-1]
        if tld in RISKY_TLDS and not trusted_domain:
            add("URL_RISKY_TLD", f"Link uses the .{tld} domain ending, often abused for phishing")

    mismatch = _text_mismatch_reason(hostname, link_text, sender_domain, sender_authenticated)
    if mismatch is not None:
        reason, strong = mismatch
        if strong:
            add("URL_TEXT_MISMATCH", reason)
        else:
            context.append(reason)

    if is_user_content_host(hostname):
        context.append(
            "URL is hosted on a public site-builder or file-sharing platform "
            "where anyone can publish pages"
        )

    if _depth == 0:
        for inner in _embedded_urls(parsed):
            inner_info = analyze_url(inner, _depth=1)
            if inner_info.suspicious:
                add(
                    "URL_REDIRECT_TO_SUSPICIOUS",
                    f"Link redirects to a suspicious address {inner_info.hostname}: "
                    + "; ".join(inner_info.reasons[:2]),
                )
                break

    normalized_path = unquote(parsed.path).lower()
    normalized_query = unquote(parsed.query).lower()
    lure_terms = [
        term
        for term in sorted(SUSPICIOUS_TERMS)
        if term in normalized_path or term in normalized_query
    ]

    # Words such as "account", "login" and "invoice" are common in
    # legitimate application URLs. Treat them as contextual evidence only:
    # another independent URL-risk indicator must already be present.
    if not trusted_domain and (reasons or context):
        for term in lure_terms:
            add("URL_LURE_TERM", f"URL contains credential or lure related term: {term}")

    suspicious = bool(reasons)

    if suspicious:
        reasons.extend(context)

    return UrlInfo(
        url=normalized,
        hostname=hostname,
        suspicious=suspicious,
        reasons=reasons if suspicious else context,
        rule_codes=codes,
        link_text=link_text,
        source=source,
    )
