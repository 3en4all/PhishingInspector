from __future__ import annotations

from dataclasses import asdict, dataclass

from .domains import registrable_domain


@dataclass(slots=True)
class AlignmentResult:
    from_domain: str | None
    return_path_domain: str | None
    dkim_domain: str | None
    spf_aligned: bool | None
    dkim_aligned: bool | None

    def to_dict(self) -> dict:
        return asdict(self)


def _organizational_domain(domain: str | None) -> str | None:
    if not domain:
        return None

    return registrable_domain(domain)


def relaxed_align(a: str | None, b: str | None) -> bool | None:
    if not a or not b:
        return None

    return _organizational_domain(a) == _organizational_domain(b)


def build_alignment(
    from_domain: str | None,
    return_path_domain: str | None,
    dkim_domain: str | None,
) -> AlignmentResult:
    return AlignmentResult(
        from_domain=from_domain,
        return_path_domain=return_path_domain,
        dkim_domain=dkim_domain,
        spf_aligned=relaxed_align(from_domain, return_path_domain),
        dkim_aligned=relaxed_align(from_domain, dkim_domain),
    )
