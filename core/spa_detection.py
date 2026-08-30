"""Heuristic detection of client-rendered (SPA) pages — neither
core/crawler.py's single-page fetch nor core/site_spider.py's graph
crawler execute JavaScript, so a React/Vue/Angular app that mounts into
an empty `<div>` looks like a near-blank page to both. That's a real
detection gap, not a bug to silently eat: this module names it so
callers can flag it rather than quietly recording "no forms, no
content" for a site that might have either.

Deliberately not a fix for the gap — a real answer needs a headless
browser (a separate, larger effort). This just makes the gap visible:
detect and log/record, don't guess at content that was never actually
rendered.
"""

import re
from dataclasses import dataclass, field

# Mount-point ids/classes every major SPA framework's default template
# uses — by far the strongest signal, since a server-rendered page has
# no reason to ship an empty div with one of these exact ids.
_ROOT_MOUNT_IDS = ("root", "app", "__next", "__nuxt", "__gatsby")

# Inline markers frameworks leave in the HTML/JS even when the shell is
# otherwise empty.
_FRAMEWORK_MARKERS = (
    "data-reactroot",
    "data-reactid",
    "ng-version",
    "__NEXT_DATA__",
    "window.__NUXT__",
    "data-server-rendered",
    "id=\"__vite-plugin",
)

# The classic Create-React-App/Vue-CLI fallback text — about as strong a
# signal as it gets.
_NOSCRIPT_RE = re.compile(
    r"<noscript>[^<]{0,200}(enable javascript|you need to enable js)",
    re.IGNORECASE,
)

# A page under this much visible text, combined with at least one bundle
# script reference, reads as "the real content isn't in this HTML."
_SHORT_TEXT_THRESHOLD = 200
_BUNDLE_SCRIPT_RE = re.compile(r"\.(?:[0-9a-f]{6,20}\.)?(?:chunk|bundle)\.js|/_next/|/static/js/")


@dataclass(frozen=True)
class SpaSignal:
    is_spa: bool = False
    reasons: tuple[str, ...] = field(default_factory=tuple)


def detect_spa(html: str, visible_text: str) -> SpaSignal:
    """`html` is the raw response body; `visible_text` is whatever text
    a caller already extracted (e.g. BeautifulSoup's `get_text()`) — kept
    as a separate param so callers that already parsed the page once
    don't pay for a second parse here."""
    reasons: list[str] = []

    if _NOSCRIPT_RE.search(html):
        reasons.append("noscript_fallback_text")

    for marker in _FRAMEWORK_MARKERS:
        if marker in html:
            reasons.append(f"framework_marker:{marker}")

    for mount_id in _ROOT_MOUNT_IDS:
        if re.search(rf'id=["\']{mount_id}["\']', html):
            reasons.append(f"root_mount:{mount_id}")

    normalized_text = " ".join(visible_text.split())
    if len(normalized_text) < _SHORT_TEXT_THRESHOLD and _BUNDLE_SCRIPT_RE.search(html):
        reasons.append("short_text_with_bundle_script")

    return SpaSignal(is_spa=bool(reasons), reasons=tuple(reasons))
