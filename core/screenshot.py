"""Playwright-based screenshot capture — evidence to support enforcement
action, unblocked by the Playwright integration already built for the
SPA rendering fallback
(core/browser_crawler.py). Same optional-dependency treatment: lazy-
imported so its absence is a clean, caught fallback, not a startup-time
failure — see requirements-browser.txt.

Deliberately narrow: one viewport screenshot of the root page, not a
full-page or multi-page capture — this is evidence/comparison material,
not a rendering pipeline. worker/pipeline.py gates *when* this runs
(first registration or content change, not every scan) to keep
Playwright launches bounded; this module only does the capture itself.

Fails closed like every other core/ module: any failure (missing
dependency, launch, navigation, timeout) returns None, never an
exception.
"""

from core.crawler import USER_AGENT

VIEWPORT = {"width": 1280, "height": 800}
CAPTURE_TIMEOUT_MS = 15_000


def capture_screenshot(domain: str, timeout_ms: int = CAPTURE_TIMEOUT_MS) -> bytes | None:
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                page = browser.new_page(user_agent=USER_AGENT, viewport=VIEWPORT)
                screenshot: bytes | None = None
                for scheme in ("https", "http"):
                    try:
                        page.goto(
                            f"{scheme}://{domain}/", timeout=timeout_ms, wait_until="networkidle"
                        )
                        screenshot = page.screenshot(type="png")
                        break
                    except PlaywrightError:
                        continue
                return screenshot
            finally:
                browser.close()
    except Exception:
        return None
