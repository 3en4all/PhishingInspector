from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class AttachmentInfo:
    filename: str
    content_type: str
    size: int
    sha256: str
    suspicious: bool = False
    reasons: list[str] = field(default_factory=list)
    # Stable rule identifiers (see scoring.RULES); reasons are for people.
    rule_codes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class UrlInfo:
    url: str
    hostname: str | None
    suspicious: bool = False
    reasons: list[str] = field(default_factory=list)
    rule_codes: list[str] = field(default_factory=list)
    # Visible text of the HTML link, when the URL came from <a href>.
    link_text: str | None = None
    # "body", "html-link", "html-form" or "attachment:<filename>".
    source: str = "body"


@dataclass(slots=True)
class Finding:
    code: str
    points: int
    message: str


@dataclass(slots=True)
class HeaderAnalysis:
    from_header: str | None
    reply_to: str | None
    return_path: str | None
    subject: str | None
    message_id: str | None
    authentication_results: list[str]
    received_headers: list[str]
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class EmailAnalysis:
    source_file: str
    headers: HeaderAnalysis
    urls: list[UrlInfo]
    attachments: list[AttachmentInfo]
    score: int
    verdict: str
    reasons: list[str]
    authentication: dict[str, Any] = field(default_factory=dict)
    received_chain: dict[str, Any] = field(default_factory=dict)
    spoofing: dict[str, Any] = field(default_factory=dict)
    content: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    # Notes about what could not be analysed (for example .msg limitations).
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def source_path(self) -> Path:
        return Path(self.source_file)

    @property
    def rule_codes(self) -> list[str]:
        return [finding.code for finding in self.findings]
