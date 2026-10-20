from __future__ import annotations

from .i18n import explain_finding as _explain


def explain_finding(reason: str) -> str:
    return _explain(reason, "en")
