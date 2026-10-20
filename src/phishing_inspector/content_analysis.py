"""Phrases typical for phishing text, in Polish and English.

Each category counts once, whatever the number of matching phrases. A single
category is weak evidence (banks also write "zaloguj się"); several categories
together are the usual phishing pattern: pressure + money + credentials.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import asdict, dataclass, field

CATEGORIES: dict[str, tuple[str, ...]] = {
    "urgency": (
        "pilne", "natychmiast", "w ciagu 24", "w ciagu 48", "w ciagu 2 godzin",
        "ostatnie ostrzezenie", "ostateczne wezwanie", "zostanie zablokowane",
        "zostanie zawieszone", "zostanie usuniete", "zablokowalismy",
        "konto zostalo zablokowane", "dostep zostanie", "wygasa dzisiaj",
        "urgent", "immediately", "within 24 hours", "within 48 hours",
        "final notice", "last warning", "will be suspended", "will be closed",
        "has been suspended", "has been locked", "account will be deleted",
        "action required", "expires today",
        "zachowac dostep", "utracisz dostep", "stracisz dostep", "utrata dostepu",
        "nie dzwon", "jestem na spotkaniu", "avoid losing access", "lose access",
        "keep access",
    ),
    "payment": (
        "doplata", "doplaty", "niedoplata", "oplata celna", "oplac", "zaplac",
        "kod blik", "platnosc blik", "przez blik", "zalegla platnosc",
        "zaleglosc", "zwrot podatku", "nadplata", "wezwanie do zaplaty",
        "faktura do zaplaty", "niezaplacona faktura", "odblokowanie przesylki",
        "customs fee", "delivery fee", "outstanding payment", "overdue invoice",
        "payment failed", "update your payment", "refund", "tax refund",
        "unpaid invoice", "pay now",
        # Business email compromise: a transfer to a new account.
        "zlec przelew", "zlecic przelew", "pilny przelew", "wykonac przelew",
        "nowy numer konta", "nowe konto kontrahenta", "zmiana numeru konta",
        "zmienil sie numer konta", "karty podarunkowe", "wire transfer",
        "new bank details", "bank details have changed", "gift cards",
    ),
    "credentials": (
        "podaj haslo", "potwierdz dane", "zweryfikuj konto", "zweryfikuj swoje",
        "weryfikacja konta", "potwierdz tozsamosc", "zaloguj sie", "kod sms",
        "dane karty", "numer karty", "kod cvv", "dane logowania", "zresetuj haslo",
        "haslo wygasa", "verify your account", "confirm your identity",
        "confirm your password", "update your account", "sign in to",
        "log in to", "your password expires", "reset your password",
        "card details", "security code", "validate your",
        "password expires", "password will expire", "keep your current password",
        "keep current password", "zachowaj obecne haslo", "zachowaj aktualne haslo",
    ),
    "threat": (
        "postepowanie egzekucyjne", "komornik", "policja", "prokuratura",
        "sprawa karna", "kara grzywny", "legal action", "lawsuit",
        "police", "arrest",
    ),
    # QR code phishing: the link is in an image so filters cannot see it.
    "qr_code": (
        "zeskanuj kod qr", "zeskanuj ponizszy kod", "zeskanuj kod telefonem",
        "zeskanuj kod qr telefonem", "scan the qr code", "scan this qr code",
        "scan the code below", "scan the qr", "zeskanuj qr",
    ),
}

POINTS_BY_CATEGORY_COUNT = {0: 0, 1: 5, 2: 15, 3: 20, 4: 25}


@dataclass(slots=True)
class ContentAnalysis:
    categories: dict[str, list[str]] = field(default_factory=dict)

    @property
    def category_count(self) -> int:
        return len(self.categories)

    @property
    def points(self) -> int:
        return POINTS_BY_CATEGORY_COUNT.get(self.category_count, 25)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["category_count"] = self.category_count
        return data


def fold_text(text: str) -> str:
    text = unicodedata.normalize("NFKD", text.lower())
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    text = text.replace("ł", "l")
    text = re.sub(r"<[^>]{0,500}>", " ", text)
    return " ".join(text.split())


def analyze_content(subject: str | None, body_text: str) -> ContentAnalysis:
    folded = fold_text(f"{subject or ''}\n{body_text or ''}")[:200_000]
    categories: dict[str, list[str]] = {}

    for category, phrases in CATEGORIES.items():
        hits = [phrase for phrase in phrases if phrase in folded]
        if hits:
            categories[category] = hits[:5]

    return ContentAnalysis(categories=categories)
