"""Brands commonly impersonated in phishing, with the domains they really use.

Edit this file to add brands. ``domains`` entries match the registrable domain
and every subdomain; a bare TLD such as ``"google"`` covers brand gTLDs
(``mail.google``). ``aliases`` are matched as whole words in the sender's
display name (case and Polish diacritics ignored; aliases of three letters or
fewer must be written in capitals, so "ING" matches but the title "Ing." does
not). ``tokens`` are the names
looked for inside other domains (``mbank-weryfikacja.com``).
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from .domains import RISKY_TLDS, registrable_domain, skeleton


@dataclass(frozen=True, slots=True)
class Brand:
    key: str
    name: str
    domains: tuple[str, ...]
    aliases: tuple[str, ...]
    tokens: tuple[str, ...]

    @property
    def primary_domain(self) -> str:
        return self.domains[0]


BRANDS: tuple[Brand, ...] = (
    # Global
    Brand("microsoft", "Microsoft",
          ("microsoft.com", "microsoftonline.com", "office.com", "office365.com",
           "outlook.com", "live.com", "hotmail.com", "sharepoint.com",
           "microsoft365.com", "msn.com", "skype.com", "azure.com",
           "windows.com", "bing.com", "microsoft"),
          ("microsoft", "microsoft 365", "office 365", "outlook", "onedrive",
           "sharepoint", "microsoft teams"),
          ("microsoft", "office365", "outlook", "onedrive", "sharepoint")),
    Brand("google", "Google",
          ("google.com", "gmail.com", "googlemail.com", "youtube.com",
           "withgoogle.com", "google-analytics.com", "googleapis.com",
           "gstatic.com", "googleusercontent.com", "googletagmanager.com",
           "doubleclick.net", "googlesyndication.com", "googleadservices.com",
           "g.co", "goo.gl", "youtu.be", "ytimg.com", "google"),
          ("google", "gmail", "google workspace"),
          ("google", "gmail")),
    Brand("apple", "Apple",
          ("apple.com", "icloud.com", "me.com", "apple"),
          ("apple", "icloud", "apple id"),
          ("apple", "icloud")),
    Brand("paypal", "PayPal",
          ("paypal.com", "paypal.me", "paypalobjects.com",
           "paypal-communication.com", "paypal-community.com"),
          ("paypal",),
          ("paypal",)),
    Brand("amazon", "Amazon",
          ("amazon.com", "amazonaws.com", "amazonses.com", "media-amazon.com",
           "ssl-images-amazon.com", "amazon"),
          ("amazon",),
          ("amazon",)),
    Brand("facebook", "Facebook / Meta",
          ("facebook.com", "facebookmail.com", "fb.com", "meta.com",
           "instagram.com", "whatsapp.com", "fbcdn.net"),
          ("facebook", "instagram", "whatsapp", "meta business"),
          ("facebook", "instagram", "whatsapp")),
    Brand("linkedin", "LinkedIn", ("linkedin.com", "licdn.com", "lnkd.in"),
          ("linkedin",), ("linkedin",)),
    Brand("netflix", "Netflix", ("netflix.com", "nflxext.com", "nflximg.net"),
          ("netflix",), ("netflix",)),
    Brand("dropbox", "Dropbox", ("dropbox.com", "dropboxmail.com"),
          ("dropbox",), ("dropbox",)),
    Brand("docusign", "DocuSign", ("docusign.com", "docusign.net"),
          ("docusign",), ("docusign",)),
    Brand("dhl", "DHL", ("dhl.com", "dhl.pl", "dhl.de", "dhlparcel.pl", "dhl"),
          ("dhl", "dhl express", "dhl parcel"), ("dhl",)),
    # Poland: banks
    Brand("pko", "PKO Bank Polski",
          ("pkobp.pl", "pko.pl", "ipko.pl", "pkoleasing.pl", "pkotfi.pl",
           "pkoubezpieczenia.pl", "pkobh.pl", "pkofaktoring.pl"),
          ("pko", "pko bp", "pko bank polski", "ipko"), ("pkobp", "ipko", "pko")),
    Brand("mbank", "mBank", ("mbank.pl", "mbank.cz", "mbank.sk"),
          ("mbank",), ("mbank",)),
    Brand("ing", "ING Bank Śląski", ("ing.pl", "ing.com", "ingbank.pl"),
          ("ing", "ing bank", "ing bank slaski"), ("ingbank", "ing")),
    Brand("pekao", "Bank Pekao", ("pekao.com.pl", "pekaobiznes24.pl"),
          ("pekao", "bank pekao"), ("pekao",)),
    Brand("santander", "Santander", ("santander.pl", "santander.com"),
          ("santander",), ("santander",)),
    Brand("millennium", "Bank Millennium", ("bankmillennium.pl",),
          ("bank millennium", "millennium"), ("millennium", "bankmillennium")),
    Brand("alior", "Alior Bank", ("aliorbank.pl",), ("alior", "alior bank"),
          ("alior", "aliorbank")),
    Brand("creditagricole", "Credit Agricole", ("credit-agricole.pl",),
          ("credit agricole",), ("creditagricole",)),
    Brand("bnp", "BNP Paribas", ("bnpparibas.pl", "bnpparibas.com"),
          ("bnp paribas",), ("bnpparibas",)),
    Brand("blik", "BLIK", ("blik.com",), ("blik",), ("blik",)),
    # Poland: parcels, marketplaces, utilities, public services
    Brand("inpost", "InPost", ("inpost.pl", "inpost.eu", "inpost.co.uk",
                               "inpost-group.com", "paczkomaty.pl"),
          ("inpost", "paczkomaty inpost"), ("inpost", "paczkomat")),
    Brand("dpd", "DPD", ("dpd.com.pl", "dpd.pl", "dpd.com", "dpd"),
          ("dpd", "dpd polska"), ("dpd",)),
    Brand("pocztapolska", "Poczta Polska",
          ("poczta-polska.pl", "pocztapolska.pl", "envelo.pl"),
          ("poczta polska",), ("pocztapolska", "poczta-polska")),
    Brand("allegro", "Allegro",
          ("allegro.pl", "allegromail.pl", "allegro.cz", "allegro.eu",
           "allegrolokalnie.pl", "allegrostatic.com", "allegroimg.com"),
          ("allegro", "allegro lokalnie", "allegro pay"), ("allegro",)),
    Brand("olx", "OLX", ("olx.pl", "olxgroup.com", "olxcdn.com"),
          ("olx",), ("olx",)),
    Brand("vinted", "Vinted", ("vinted.pl", "vinted.com", "vinted.net"),
          ("vinted",), ("vinted",)),
    Brand("orlen", "Orlen", ("orlen.pl",), ("orlen",), ("orlen",)),
    Brand("pge", "PGE", ("gkpge.pl", "pge.pl", "pge-obrot.pl"),
          ("pge", "pge obrot"), ("pge",)),
    Brand("tauron", "Tauron", ("tauron.pl", "tauron-dystrybucja.pl"),
          ("tauron",), ("tauron",)),
    Brand("enea", "Enea", ("enea.pl",), ("enea",), ("enea",)),
    Brand("energa", "Energa", ("energa.pl", "energa-operator.pl"),
          ("energa",), ("energa",)),
    Brand("govpl", "gov.pl / mObywatel / ePUAP",
          ("gov.pl", "mobywatel.gov.pl", "epuap.gov.pl"),
          ("mobywatel", "epuap", "gov.pl", "urzad skarbowy",
           "krajowa administracja skarbowa", "ministerstwo finansow",
           "e-urzad skarbowy"),
          ("mobywatel", "epuap")),
    Brand("zus", "ZUS", ("zus.pl",), ("zus",), ("zus",)),
)

# Brand domains used for "looks like" comparisons in older code and tests.
BRAND_DOMAINS: frozenset[str] = frozenset(
    brand.primary_domain for brand in BRANDS
)


def _fold(text: str) -> str:
    text = unicodedata.normalize("NFKD", text.lower())
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    return text.replace("ł", "l")


def brand_owning(domain: str | None) -> Brand | None:
    """The brand that really owns ``domain`` (any subdomain counts)."""
    if not domain:
        return None

    host = domain.lower().strip(".")
    registered = registrable_domain(host)
    label = registered.split(".", 1)[0] if registered else ""

    for brand in BRANDS:
        for owned in brand.domains:
            if "." not in owned:
                # Brand gTLD (``.google``) or the brand label under any ccTLD,
                # for example ``paypal.pl`` or ``dhl.de``.
                if host.endswith("." + owned):
                    return brand
                continue

            if registered == owned or host == owned or host.endswith("." + owned):
                return brand

        suffix = registered.rsplit(".", 1)[-1] if registered else ""
        if (
            label
            and label == brand.key
            and len(label) >= 3
            and suffix not in RISKY_TLDS
        ):
            return brand

    return None


_WORD_CACHE: dict[str, re.Pattern[str]] = {}


def _is_short(alias: str) -> bool:
    return len(_fold(alias)) <= 3


def _alias_pattern(alias: str) -> re.Pattern[str]:
    pattern = _WORD_CACHE.get(alias)
    if pattern is None:
        if _is_short(alias):
            # Short names collide with ordinary words and titles ("Ing. Jan
            # Novak", "Pge"); brands write them in capitals.
            pattern = re.compile(
                r"(?<![A-Za-z0-9])" + re.escape(_fold(alias).upper()) + r"(?![A-Za-z0-9])"
            )
        else:
            pattern = re.compile(r"(?<![a-z0-9])" + re.escape(_fold(alias)) + r"(?![a-z0-9])")
        _WORD_CACHE[alias] = pattern
    return pattern


def brand_in_text(text: str | None) -> Brand | None:
    """A brand named in short text such as a display name ("mBank S.A.")."""
    if not text:
        return None

    folded = _fold(text)
    upper = unicodedata.normalize("NFKD", text)
    upper = "".join(ch for ch in upper if not unicodedata.combining(ch)).replace("Ł", "L")

    for brand in BRANDS:
        for alias in brand.aliases:
            haystack = upper if _is_short(alias) else folded
            if _alias_pattern(alias).search(haystack):
                return brand

    return None


def _similarity(a: str, b: str) -> float:
    from .domain_analysis import levenshtein_distance

    longest = max(len(a), len(b))
    if longest == 0:
        return 1.0
    return 1.0 - levenshtein_distance(a, b) / longest


def imitated_brand(domain: str | None) -> tuple[Brand, str, float] | None:
    """Detect a domain that imitates a brand it does not belong to.

    Returns ``(brand, kind, similarity)`` where kind is ``"lookalike"``
    (``micros0ft.com``, ``pаypal.com``) or ``"brand-name"``
    (``mbank-weryfikacja.com``, ``inpost-paczka24.xyz``).
    """
    if not domain or brand_owning(domain) is not None:
        return None

    registered = registrable_domain(domain)
    if not registered:
        return None

    label = registered.split(".", 1)[0]
    label_skeleton = skeleton(label)
    parts = [part for part in re.split(r"[-_]", label_skeleton) if part]

    best: tuple[Brand, str, float] | None = None

    for brand in BRANDS:
        tokens = set(brand.tokens) | {brand.key}

        for token in tokens:
            token = token.replace("-", "")

            if label_skeleton.replace("-", "") == token:
                # Same letters as the brand: either a homoglyph/digit swap
                # (micros0ft) or the brand label on a domain it does not own
                # (paypal.top).
                kind = "lookalike" if label != token else "brand-name"
                return brand, kind, 1.0

            if len(token) >= 7:
                similarity = _similarity(label_skeleton.replace("-", ""), token)
                if similarity >= 0.85 and (best is None or similarity > best[2]):
                    best = (brand, "lookalike", similarity)

            if len(parts) > 1:
                for part in parts:
                    if part == token:
                        return brand, "brand-name", 1.0
                    if len(token) >= 7 and _similarity(part, token) >= 0.85:
                        candidate = (brand, "brand-name", _similarity(part, token))
                        if best is None or candidate[2] > best[2]:
                            best = candidate

    return best
