"""Content-based website crawler — data acquisition for incident
detection. Deliberately not screenshot-based: this fetches and parses
the actual page content to detect forms (a strong phishing/credential-
harvesting signal), cross-domain redirects (parking pages, or a
lookalike bouncing to the real site to look legitimate), and content
changes over time via a hash — all cheap compared to running a headless
browser, which is a separate, larger effort.

Fails closed like every other core/ module: a fetch/parse failure
returns an "unreachable" snapshot, never an exception. Most candidate
domains being crawled are unregistered or parked with nothing behind
them — that's the expected common case, not an error.
"""

import hashlib
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

from core.spa_detection import detect_spa

USER_AGENT = "DomainNameWatch/1.0 (+mailto:ops@example.com)"
MAX_CONTENT_BYTES = 2_000_000  # don't pull an unbounded response body
MAX_REDIRECTS = 5


@dataclass(frozen=True)
class WebsiteSnapshot:
    reachable: bool = False
    status_code: int | None = None
    final_url: str | None = None
    content_hash: str | None = None
    has_forms: bool = False
    form_count: int = 0
    has_password_field: bool = False
    redirect_target: str | None = None  # set only if it redirected to a *different* domain
    text_snippet: str = field(default="")  # short excerpt, for display — not used in diffing
    # This crawler is server-render-only (no JS execution) — a client-
    # rendered SPA mounting into an empty shell looks like blank content
    # to it. See core/spa_detection.py: flagged here so that gap is
    # visible rather than silently read as "no forms, no content."
    is_spa: bool = False
    spa_signals: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        return {
            "reachable": self.reachable,
            "status_code": self.status_code,
            "final_url": self.final_url,
            "content_hash": self.content_hash,
            "has_forms": self.has_forms,
            "form_count": self.form_count,
            "has_password_field": self.has_password_field,
            "redirect_target": self.redirect_target,
            "text_snippet": self.text_snippet,
            "is_spa": self.is_spa,
            "spa_signals": list(self.spa_signals),
        }

    @classmethod
    def from_dict(cls, data: dict | None) -> "WebsiteSnapshot":
        if not data:
            return cls()
        fields = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        if "spa_signals" in fields:
            fields["spa_signals"] = tuple(fields["spa_signals"])
        return cls(**fields)


def _registrable_host(url: str) -> str:
    host = urlparse(url).hostname or ""
    return host.removeprefix("www.").lower()


def snapshot_from_html(
    html: str, *, status_code: int, final_url: str, requested_domain: str
) -> WebsiteSnapshot:
    """Shared parsing core behind both fetch paths: `crawl_website`
    (requests, server-rendered content) and
    core/browser_crawler.py's `render_with_browser` (Playwright, for
    domains the fast path already flagged `is_spa` — see
    core/spa_detection.py). Same form/password/hash/SPA analysis either
    way; only how the HTML was obtained differs."""
    final_host = _registrable_host(final_url)
    requested_host = requested_domain.removeprefix("www.").lower()
    redirect_target = final_url if final_host and final_host != requested_host else None

    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        soup = None

    forms = soup.find_all("form") if soup else []
    has_password_field = bool(soup and soup.find("input", attrs={"type": "password"}))
    text = soup.get_text(separator=" ", strip=True) if soup else html
    normalized_text = " ".join(text.split())
    content_hash = hashlib.sha256(normalized_text.encode("utf-8")).hexdigest()
    spa_signal = detect_spa(html, normalized_text)

    return WebsiteSnapshot(
        reachable=True,
        status_code=status_code,
        final_url=final_url,
        content_hash=content_hash,
        has_forms=len(forms) > 0,
        form_count=len(forms),
        has_password_field=has_password_field,
        redirect_target=redirect_target,
        text_snippet=normalized_text[:280],
        is_spa=spa_signal.is_spa,
        spa_signals=spa_signal.reasons,
    )


def crawl_website(domain: str, timeout: float = 10.0) -> WebsiteSnapshot:
    session = requests.Session()
    session.max_redirects = MAX_REDIRECTS

    response = None
    for scheme in ("https", "http"):
        try:
            response = session.get(
                f"{scheme}://{domain}/",
                timeout=timeout,
                headers={"User-Agent": USER_AGENT},
                allow_redirects=True,
                stream=True,
            )
            break
        except requests.RequestException:
            continue

    if response is None:
        return WebsiteSnapshot(reachable=False)

    try:
        raw = response.raw.read(MAX_CONTENT_BYTES, decode_content=True)
        body = raw.decode(response.encoding or "utf-8", errors="replace")
    except Exception:
        return WebsiteSnapshot(reachable=False, status_code=response.status_code)
    finally:
        response.close()

    return snapshot_from_html(
        body, status_code=response.status_code, final_url=response.url, requested_domain=domain
    )
