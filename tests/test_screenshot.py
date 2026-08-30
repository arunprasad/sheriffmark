"""Unit tests for core/screenshot.py, mocking playwright.sync_api via
sys.modules — same approach as tests/test_browser_crawler.py, so these
run without the real (optional) Playwright dependency installed."""

import sys
from unittest.mock import MagicMock, patch


class _FakePlaywrightError(Exception):
    pass


def _fake_playwright_module(*, goto_side_effect=None, screenshot_bytes=b"fake-png-bytes"):
    page = MagicMock()
    page.screenshot.return_value = screenshot_bytes
    if goto_side_effect is not None:
        page.goto.side_effect = goto_side_effect

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


class TestCaptureScreenshot:
    def test_missing_playwright_returns_none(self):
        from core.screenshot import capture_screenshot

        with patch.dict(sys.modules, {"playwright.sync_api": None}):
            result = capture_screenshot("example.com")

        assert result is None

    def test_successful_capture_returns_png_bytes(self):
        from core.screenshot import capture_screenshot

        fake_module, page, browser = _fake_playwright_module(screenshot_bytes=b"real-png-bytes")

        with patch.dict(sys.modules, {"playwright.sync_api": fake_module}):
            result = capture_screenshot("example.com")

        assert result == b"real-png-bytes"
        browser.close.assert_called_once()

    def test_both_schemes_failing_returns_none(self):
        from core.screenshot import capture_screenshot

        fake_module, _, browser = _fake_playwright_module(
            goto_side_effect=_FakePlaywrightError("nav failed")
        )

        with patch.dict(sys.modules, {"playwright.sync_api": fake_module}):
            result = capture_screenshot("nowhere.example")

        assert result is None
        browser.close.assert_called_once()

    def test_unexpected_exception_returns_none_not_raise(self):
        from core.screenshot import capture_screenshot

        fake_module = MagicMock()
        fake_module.sync_playwright.side_effect = RuntimeError("chromium not installed")
        fake_module.Error = _FakePlaywrightError

        with patch.dict(sys.modules, {"playwright.sync_api": fake_module}):
            result = capture_screenshot("example.com")

        assert result is None
