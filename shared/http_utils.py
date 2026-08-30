"""Shared HTTP response parsing used by more than one core/ module —
kept here instead of duplicated so the rate-limit-aware callers
(core/registration.py's RDAP client, core/ct_poller.py's crt.sh client)
parse the `Retry-After` header identically.
"""

from datetime import UTC, datetime
from email.utils import parsedate_to_datetime


def parse_retry_after(raw: str | None) -> float | None:
    """`Retry-After` (RFC 9110 §10.2.3) is either a delay in seconds or
    an HTTP-date — handle both. Fails closed (`None`) on anything else,
    including a negative/garbled value, so a malformed header from a
    misbehaving server never raises or produces a nonsensical delay."""
    if not raw:
        return None
    raw = raw.strip()

    try:
        return max(0.0, float(raw))
    except ValueError:
        pass

    try:
        target = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return None
    if target.tzinfo is None:
        target = target.replace(tzinfo=UTC)
    return max(0.0, (target - datetime.now(UTC)).total_seconds())
