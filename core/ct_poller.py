"""Certificate Transparency log polling via crt.sh's JSON search API.

Incremental: caller passes the highest crt.sh certificate id seen on the
previous run (`since_cert_id`) and gets back only newer entries plus the
new high-water mark to persist.

crt.sh is a free, shared community service and is empirically flaky — a
502 from its backend is a real, reproducible occurrence (hit at least
four separate times during this project's own development, including
this retry logic's own live verification, which caught crt.sh down
*again* while testing the fix for it). This module
retries transient failures with backoff before giving up, and treats any
still-failing fetch/parse as `success=False` with no hits, never an
exception — callers (the worker) should treat that as "try again next
run", not a pipeline failure, and should not confuse it with a genuine
"no new certs" result.

No independent second CT source is used as a fallback here — checked
two real candidates and both turned out unsuitable: SSLMate's Cert
Spotter API requires monitoring a specific registrable domain you
control, not free-text substring search across all issued certs (it
explicitly rejects a bare keyword like "acme" with "not beneath an eTLD
available for public registration") — a fundamentally different product
from what crt.sh's `%keyword%` search does. crt.sh's own direct
read-only Postgres endpoint (`crt.sh:5432`, public `guest` login) is
real and reachable, but query latency there was ten-plus seconds even
for schema introspection during testing — not something to build
reliability on, and still the same underlying organization/outage
domain as the HTTP API anyway. Retry-with-backoff on crt.sh itself is
the properly-scoped fix for what's actually achievable here; true
multi-source CT redundancy is an open item, not solved by this module.
"""

import logging
import time
from dataclasses import dataclass
from datetime import datetime

import requests

from shared.http_utils import parse_retry_after

logger = logging.getLogger(__name__)

USER_AGENT = "DomainNameWatch/1.0 (+mailto:ops@example.com)"
CRTSH_URL = "https://crt.sh/"
DEFAULT_RETRIES = 3
DEFAULT_BACKOFF_SECONDS = 2.0


@dataclass(frozen=True)
class CertHit:
    cert_id: int
    common_name: str
    issued_at: datetime | None


@dataclass(frozen=True)
class CTPollResult:
    success: bool
    hits: list[CertHit]
    max_cert_id: int | None  # new cursor to persist, only meaningful if success
    # Distinguishes "crt.sh told us to back off" from every other
    # failure mode (5xx, timeout, bad JSON) — those are worth retrying
    # immediately with backoff (this project's own crt.sh outages have
    # all been transient 502s); hammering the same request again right
    # after a 429 isn't. See worker/pipeline.py's RateLimiter.
    rate_limited: bool = False
    retry_after_seconds: float | None = None


def poll_ct_logs(
    keyword: str,
    since_cert_id: int = 0,
    session: requests.Session | None = None,
    timeout: float = 20.0,
    retries: int = DEFAULT_RETRIES,
    backoff_seconds: float = DEFAULT_BACKOFF_SECONDS,
) -> CTPollResult:
    """Search crt.sh for certificates whose common name contains `keyword`,
    returning only entries newer than `since_cert_id`.

    Retries transient failures (network error, timeout, 5xx) up to
    `retries` times with linear backoff before giving up — a single 502
    (crt.sh's most common failure mode, observed live during this
    project's development) shouldn't cost a whole day's CT coverage for
    a brand if the service recovers within a few seconds.
    """
    http = session or requests
    entries = None
    last_error: Exception | None = None

    for attempt in range(1, retries + 1):
        try:
            resp = http.get(
                CRTSH_URL,
                params={"q": f"%{keyword}%", "output": "json"},
                timeout=timeout,
                headers={"User-Agent": USER_AGENT},
            )
            if resp.status_code == 429:
                retry_after = parse_retry_after(resp.headers.get("Retry-After"))
                logger.warning(
                    "crt.sh rate limit hit for keyword %r — backing off instead of retrying "
                    "immediately",
                    keyword,
                )
                return CTPollResult(
                    success=False,
                    hits=[],
                    max_cert_id=None,
                    rate_limited=True,
                    retry_after_seconds=retry_after,
                )
            resp.raise_for_status()
            entries = resp.json()
            break
        except (requests.RequestException, ValueError) as e:
            last_error = e
            if attempt < retries:
                logger.warning(
                    "crt.sh poll attempt %d/%d failed (%s), retrying in %.0fs",
                    attempt,
                    retries,
                    e,
                    backoff_seconds * attempt,
                )
                time.sleep(backoff_seconds * attempt)

    if entries is None:
        logger.warning("crt.sh poll failed after %d attempts: %s", retries, last_error)
        return CTPollResult(success=False, hits=[], max_cert_id=None)

    hits: list[CertHit] = []
    max_id = since_cert_id
    for entry in entries:
        cert_id = entry.get("id")
        if cert_id is None or cert_id <= since_cert_id:
            continue
        max_id = max(max_id, cert_id)
        hits.append(
            CertHit(
                cert_id=cert_id,
                common_name=entry.get("common_name", ""),
                issued_at=_parse_timestamp(entry.get("entry_timestamp")),
            )
        )

    return CTPollResult(success=True, hits=hits, max_cert_id=max_id)


def _parse_timestamp(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None
