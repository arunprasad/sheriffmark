"""Unit tests for the Playwright fallback, mocking the (optional)
playwright.sync_api module itself via sys.modules rather than requiring
it installed — same "test the lazy-import boundary without needing the
real dependency" approach as web/api/saml_auth.py's tests. Live
rendering against a real SPA is verified manually.
"""

import sys
from unittest.mock import MagicMock, patch

from core.crawler import WebsiteSnapshot


class _FakePlaywrightError(Exception):
    pass


def _fake_playwright_module(*, goto_side_effect=None, html="<html></html>", status=200, url=None):
    """Builds a fake playwright.sync_api module exposing just enough of
    the real API surface for core/browser_crawler.py to drive."""
    page = MagicMock()
    page.content.return_value = html
    page.url = url or "https://example.com/"

    response = MagicMock()
    response.status = status

    if goto_side_effect is not None:
        page.goto.side_effect = goto_side_effect
    else:
        page.goto.return_value = response

    browser = MagicMock()
    browser.new_page.return_value = page

    chromium = MagicMock()
    chromium.launch.return_value = browser

    playwright_instance = MagicMock()
    playwright_instance.chromium = chromium

    sync_playwright_cm = MagicMock()
    sync_playwright_cm.__enter__.return_value = playwright_instance
    sync_playwright_cm.__exit__.return_value = False

    fake_module = MagicMock()
    fake_module.sync_playwright.return_value = sync_playwright_cm
    fake_module.Error = _FakePlaywrightError
    return fake_module, page, browser


class TestRenderWithBrowser:
    def test_missing_playwright_returns_unreachable(self):
        from core.browser_crawler import render_with_browser

        with patch.dict(sys.modules, {"playwright.sync_api": None}):
            snap = render_with_browser("example.com")

        assert snap == WebsiteSnapshot(reachable=False)

    def test_successful_render_returns_a_real_snapshot(self):
        from core.browser_crawler import render_with_browser

        html = '<html><body><form><input type="password"></form>Real content here.</body></html>'
        fake_module, page, browser = _fake_playwright_module(
            html=html, status=200, url="https://spa.example/"
        )

        with patch.dict(sys.modules, {"playwright.sync_api": fake_module}):
            snap = render_with_browser("spa.example")

        assert snap.reachable is True
        assert snap.status_code == 200
        assert snap.final_url == "https://spa.example/"
        assert snap.has_forms is True
        assert snap.has_password_field is True
        browser.close.assert_called_once()  # always cleaned up

    def test_both_schemes_failing_returns_unreachable(self):
        from core.browser_crawler import render_with_browser

        fake_module, _, browser = _fake_playwright_module(
            goto_side_effect=_FakePlaywrightError("nav failed")
        )

        with patch.dict(sys.modules, {"playwright.sync_api": fake_module}):
            snap = render_with_browser("nowhere.example")

        assert snap == WebsiteSnapshot(reachable=False)
        browser.close.assert_called_once()

    def test_https_failure_falls_back_to_http(self):
        from core.browser_crawler import render_with_browser

        response = MagicMock()
        response.status = 200
        page = MagicMock()
        page.content.return_value = "<html><body>ok</body></html>"
        page.url = "http://plain.example/"
        page.goto.side_effect = [_FakePlaywrightError("https failed"), response]

        browser = MagicMock()
        browser.new_page.return_value = page
        chromium = MagicMock()
        chromium.launch.return_value = browser
        playwright_instance = MagicMock()
        playwright_instance.chromium = chromium
        sync_playwright_cm = MagicMock()
        sync_playwright_cm.__enter__.return_value = playwright_instance
        sync_playwright_cm.__exit__.return_value = False
        fake_module = MagicMock()
        fake_module.sync_playwright.return_value = sync_playwright_cm
        fake_module.Error = _FakePlaywrightError

        with patch.dict(sys.modules, {"playwright.sync_api": fake_module}):
            snap = render_with_browser("plain.example")

        assert snap.reachable is True
        assert page.goto.call_count == 2

    def test_unexpected_exception_returns_unreachable_not_raise(self):
        from core.browser_crawler import render_with_browser

        fake_module = MagicMock()
        fake_module.sync_playwright.side_effect = RuntimeError("chromium not installed")
        fake_module.Error = _FakePlaywrightError

        with patch.dict(sys.modules, {"playwright.sync_api": fake_module}):
            snap = render_with_browser("example.com")

        assert snap == WebsiteSnapshot(reachable=False)
