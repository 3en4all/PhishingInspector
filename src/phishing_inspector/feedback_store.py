from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .runtime_paths import app_data_dir


DATA_DIR = app_data_dir()
RATING_STATE_FILE = DATA_DIR / "rating_state.json"

SUPABASE_URL = "https://bfvfunmbynqmmvrxueqj.supabase.co"
SUPABASE_PUBLISHABLE_KEY = "sb_publishable_W0uWNkzwKaqQQcRBtTQ0Qw_uk0Kz1OI"

APP_RATING_COOLDOWN_DAYS = 7
NETWORK_TIMEOUT_SECONDS = 5

_ALLOWED_FEEDBACK = {
    "correct",
    "false_positive",
    "confirmed_phishing",
    "unsure",
}

_RULE_CODE_RE = re.compile(r"[A-Z][A-Z0-9_]{1,63}")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _rpc(function_name: str, payload: dict[str, Any]) -> bool:
    request = urllib.request.Request(
        f"{SUPABASE_URL}/rest/v1/rpc/{function_name}",
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        method="POST",
        headers={
            "apikey": SUPABASE_PUBLISHABLE_KEY,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=NETWORK_TIMEOUT_SECONDS,
        ) as response:
            return 200 <= int(response.status) < 300
    except (OSError, urllib.error.URLError, urllib.error.HTTPError):
        return False


def _clean_codes(codes: list[str] | None) -> list[str]:
    result: list[str] = []
    for code in codes or []:
        code = str(code)
        if _RULE_CODE_RE.fullmatch(code) and code not in result:
            result.append(code)
    return result[:50]


def submit_scan_feedback_cloud(
    *,
    verdict: str,
    score: int,
    feedback: str,
    app_version: str,
    authentication: dict[str, Any] | None = None,
    finding_codes: list[str] | None = None,
    url_rule_codes: list[str] | None = None,
    attachment_rule_codes: list[str] | None = None,
) -> bool:
    if feedback not in _ALLOWED_FEEDBACK:
        raise ValueError("Unsupported feedback value")

    auth = authentication or {}

    payload = {
        "p_scan_id": None,
        "p_app_version": app_version,
        "p_engine_version": app_version,
        "p_verdict": verdict,
        "p_score": int(score),
        "p_feedback": feedback,
        # Only stable rule codes are sent, never addresses, URLs or file names.
        "p_finding_codes": _clean_codes(finding_codes),
        "p_url_rule_codes": _clean_codes(url_rule_codes),
        "p_attachment_rule_codes": _clean_codes(attachment_rule_codes),
        "p_spf": auth.get("spf"),
        "p_dkim": auth.get("dkim"),
        "p_dmarc": auth.get("dmarc"),
    }

    # Public beta privacy policy:
    # no local persistence and no disk-backed retry queue.
    return _rpc("submit_scan_feedback", payload)


def submit_app_rating_cloud(rating: int, *, app_version: str) -> bool:
    rating = int(rating)

    if rating < 1 or rating > 5:
        raise ValueError("Rating must be between 1 and 5")

    payload = {
        "p_rating": rating,
        "p_app_version": app_version,
        "p_engine_version": app_version,
    }

    # Public beta privacy policy:
    # no local persistence and no disk-backed retry queue.
    return _rpc("submit_app_rating", payload)


def should_prompt_for_app_rating(
    cooldown_days: int = APP_RATING_COOLDOWN_DAYS,
) -> bool:
    if cooldown_days <= 0:
        return True

    if not RATING_STATE_FILE.exists():
        return True

    try:
        state = json.loads(RATING_STATE_FILE.read_text(encoding="utf-8"))
        raw = state.get("last_prompted_at")

        if not raw:
            return True

        last = datetime.fromisoformat(str(raw))

        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)

        return _utc_now() - last >= timedelta(days=cooldown_days)
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return True


def mark_app_rating_prompted() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    RATING_STATE_FILE.write_text(
        json.dumps(
            {"last_prompted_at": _utc_now().isoformat()},
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
