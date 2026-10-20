from __future__ import annotations

import re
from dataclasses import dataclass, field
from email.message import Message

from .domains import registrable_domain

RESULT_PATTERN = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z0-9_-]+)", re.I)
DKIM_DOMAIN_PATTERN = re.compile(r"\bheader\.d\s*=\s*([^\s;]+)", re.I)

_PASSING = {"pass"}
_KNOWN_RESULTS = {
    "pass", "fail", "softfail", "neutral", "none", "temperror", "permerror",
}


@dataclass(slots=True)
class AuthAnalysis:
    spf: str
    dkim: str
    dmarc: str
    dkim_domain: str | None
    raw_headers: list[str]
    warnings: list[str]
    # Server that wrote the header the results were taken from ("" when the
    # header has no authserv-id, as in Microsoft 365).
    authserv_id: str | None = None
    # Authentication-Results headers from other servers. Anyone can put such
    # a header into a message before sending it, so they never count.
    ignored_headers: list[str] = field(default_factory=list)
    # The ignored headers claim a pass that the trusted header does not.
    forged_pass_claim: bool = False
    # False when the message has Received headers but none of them was
    # written by the server named in the trusted header, so the header may
    # have been added by someone else.
    verified: bool = True


def _normalize_result(value: str | None) -> str:
    if not value:
        return "unknown"

    value = value.lower()

    if value in _KNOWN_RESULTS:
        return value

    return "unknown"


def _authserv_id(header: str) -> str:
    """The authserv-id is the first element, before the first ';'.

    Microsoft 365 omits it and starts directly with ``spf=...``.
    """
    first = " ".join(str(header).split()).split(";", 1)[0].strip()

    if "=" in first:
        return ""

    return first.split()[0].lower() if first else ""


def _results(header: str) -> dict[str, str]:
    results: dict[str, str] = {}

    for key, value in RESULT_PATTERN.findall(header):
        key = key.lower()
        if key not in results:
            results[key] = _normalize_result(value)

    return results


def parse_authentication_results(message: Message) -> AuthAnalysis:
    raw_headers = [str(h) for h in message.get_all("Authentication-Results", failobj=[])]

    results = {
        "spf": "unknown",
        "dkim": "unknown",
        "dmarc": "unknown",
    }

    dkim_domain: str | None = None
    authserv_id: str | None = None
    ignored: list[str] = []
    forged_pass_claim = False

    # The receiving server adds its header on top, so the first header is the
    # one from the mailbox provider. Only headers written by that same server
    # are used; headers lower in the message may come from the sender.
    if raw_headers:
        authserv_id = _authserv_id(raw_headers[0])

    trusted = [h for h in raw_headers if _authserv_id(h) == authserv_id]
    ignored = [h for h in raw_headers if _authserv_id(h) != authserv_id]

    for header in trusted:
        for key, value in _results(header).items():
            if results[key] == "unknown":
                results[key] = value

        if dkim_domain is None:
            match = DKIM_DOMAIN_PATTERN.search(header)
            if match:
                dkim_domain = match.group(1).strip().lower()

    warnings: list[str] = []
    verified = True

    received = [str(h).lower() for h in message.get_all("Received", failobj=[])]
    if authserv_id and received:
        server = authserv_id.strip("[]")
        org = registrable_domain(server)
        if not any(server in h or (org and org in h) for h in received):
            verified = False
            warnings.append(
                f"Authentication-Results server {authserv_id} does not appear in "
                "the Received chain; results treated as unverified"
            )

    for header in ignored:
        for key, value in _results(header).items():
            if value in _PASSING and results[key] not in _PASSING:
                forged_pass_claim = True

    for key in ("spf", "dkim", "dmarc"):
        result = results[key]

        if result == "fail":
            warnings.append(f"{key.upper()} authentication failed")
        elif result == "softfail":
            warnings.append(f"{key.upper()} authentication soft-failed")
        elif result in {"temperror", "permerror"}:
            warnings.append(f"{key.upper()} authentication returned {result}")

    if ignored:
        warnings.append(
            f"{len(ignored)} Authentication-Results header(s) from another server "
            "were ignored"
        )

    if forged_pass_claim:
        warnings.append(
            "An untrusted Authentication-Results header claims a pass that the "
            "receiving server did not confirm"
        )

    return AuthAnalysis(
        spf=results["spf"],
        dkim=results["dkim"],
        dmarc=results["dmarc"],
        dkim_domain=dkim_domain,
        raw_headers=raw_headers,
        warnings=warnings,
        authserv_id=authserv_id,
        ignored_headers=ignored,
        forged_pass_claim=forged_pass_claim,
        verified=verified,
    )
