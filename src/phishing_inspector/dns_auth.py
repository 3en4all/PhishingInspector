from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(slots=True)
class DnsRecordCheck:
    domain: str
    record_type: str
    status: str
    records: list[str]
    warnings: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


def _query_txt_records(domain: str) -> list[str]:
    try:
        import dns.resolver  # type: ignore
    except ImportError:
        return []

    answers = dns.resolver.resolve(domain, "TXT", lifetime=5.0)
    records: list[str] = []

    for answer in answers:
        if hasattr(answer, "strings"):
            parts = [
                part.decode("utf-8", errors="replace")
                if isinstance(part, bytes)
                else str(part)
                for part in answer.strings
            ]
            records.append("".join(parts))
        else:
            records.append(str(answer).strip('"'))

    return records


def check_spf_record(domain: str) -> DnsRecordCheck:
    warnings: list[str] = []

    try:
        records = _query_txt_records(domain)
    except Exception as exc:
        return DnsRecordCheck(
            domain=domain,
            record_type="SPF",
            status="error",
            records=[],
            warnings=[f"DNS lookup failed: {type(exc).__name__}: {exc}"],
        )

    if not records:
        return DnsRecordCheck(
            domain=domain,
            record_type="SPF",
            status="unknown",
            records=[],
            warnings=["No TXT records available or dnspython is not installed"],
        )

    spf = [record for record in records if record.lower().startswith("v=spf1")]

    if not spf:
        warnings.append("No SPF record found")
        status = "missing"
    elif len(spf) > 1:
        warnings.append("Multiple SPF records found")
        status = "invalid"
    else:
        status = "present"

    return DnsRecordCheck(
        domain=domain,
        record_type="SPF",
        status=status,
        records=spf,
        warnings=warnings,
    )


def check_dmarc_record(domain: str) -> DnsRecordCheck:
    query_domain = f"_dmarc.{domain}"
    warnings: list[str] = []

    try:
        records = _query_txt_records(query_domain)
    except Exception as exc:
        return DnsRecordCheck(
            domain=query_domain,
            record_type="DMARC",
            status="error",
            records=[],
            warnings=[f"DNS lookup failed: {type(exc).__name__}: {exc}"],
        )

    if not records:
        return DnsRecordCheck(
            domain=query_domain,
            record_type="DMARC",
            status="unknown",
            records=[],
            warnings=["No TXT records available or dnspython is not installed"],
        )

    dmarc = [record for record in records if record.lower().startswith("v=dmarc1")]

    if not dmarc:
        warnings.append("No DMARC record found")
        status = "missing"
    elif len(dmarc) > 1:
        warnings.append("Multiple DMARC records found")
        status = "invalid"
    else:
        status = "present"

    return DnsRecordCheck(
        domain=query_domain,
        record_type="DMARC",
        status=status,
        records=dmarc,
        warnings=warnings,
    )
