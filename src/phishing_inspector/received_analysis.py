from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
from email.message import Message

IP_PATTERN = re.compile(r"(?<![\w:])((?:\d{1,3}\.){3}\d{1,3})(?![\w:])")


@dataclass(slots=True)
class ReceivedHop:
    index: int
    raw: str
    ips: list[str]


@dataclass(slots=True)
class ReceivedAnalysis:
    hops: list[ReceivedHop]
    originating_ip: str | None
    warnings: list[str]


def _is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def analyze_received_chain(message: Message) -> ReceivedAnalysis:
    received = list(message.get_all("Received", failobj=[]))
    hops: list[ReceivedHop] = []
    warnings: list[str] = []

    for index, header in enumerate(received):
        ips: list[str] = []
        for candidate in IP_PATTERN.findall(header):
            if _is_valid_ip(candidate) and candidate not in ips:
                ips.append(candidate)

        hops.append(ReceivedHop(index=index, raw=header, ips=ips))

    originating_ip: str | None = None

    if hops and hops[-1].ips:
        originating_ip = hops[-1].ips[0]

    if not received:
        warnings.append("No Received headers were found")
    elif originating_ip is None:
        warnings.append("Could not derive an originating IP from Received headers")

    return ReceivedAnalysis(
        hops=hops,
        originating_ip=originating_ip,
        warnings=warnings,
    )
