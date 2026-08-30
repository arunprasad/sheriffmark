"""Browser-based rendering fallback for domains the fast path already
flagged `is_spa` (core/spa_detection.py). Playwright, not Selenium —
modern API, auto-waiting, and what Scrapy's own ecosystem
(scrapy-playwright) has standardized on.

Deliberately narrow scope, matching how this gap was flagged: renders
and snapshots just the root page for a domain already known to need
it — not a second full graph crawl (core/site_spider.py's depth-2/
25-page crawl stays requests-based; browser rendering is reserved for
the minority of domains where it's actually needed, since a headless
browser costs far more time/memory per page than a plain fetch).

Optional dependency, same reasoning as SAML's python3-saml
(web/api/saml_auth.py): Playwright needs its own Chromium download
(`playwright install chromium`, ~300MB) on top of the pip package, real
weight a deployment that never sees SPA-flagged domains shouldn't have
to carry. Imported lazily so its absence is a clear, caught failure —
not a startup-time ImportError for every self-hoster.

Fails closed like every other core/ module: any failure (missing
dependency, launch, navigation, timeout) returns an unreachable
WebsiteSnapshot, never an exception.
"""

from core.crawler import USER_AGENT, WebsiteSnapshot, snapshot_from_html

RENDER_TIMEOUT_MS = 15_000


def render_with_browser(domain: str, timeout_ms: int = RENDER_TIMEOUT_MS) -> WebsiteSnapshot:
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError:
        return WebsiteSnapshot(reachable=False)

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                page = browser.new_page(user_agent=USER_AGENT)
                response = None
                for scheme in ("https", "http"):
                    try:
                        response = page.goto(
                            f"{scheme}://{domain}/", timeout=timeout_ms, wait_until="networkidle"
                        )
                        break
                    except PlaywrightError:
                        continue
                if response is None:
                    return WebsiteSnapshot(reachable=False)

                html = page.content()
                status_code = response.status
                final_url = page.url
            finally:
                browser.close()
    except Exception:
        return WebsiteSnapshot(reachable=False)

    return snapshot_from_html(
        html, status_code=status_code, final_url=final_url, requested_domain=domain
    )
