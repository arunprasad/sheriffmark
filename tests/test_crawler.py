from unittest.mock import MagicMock, patch

import requests

from core.crawler import crawl_website


def _mock_response(url, status_code=200, body=b"<html><body>hi</body></html>", encoding="utf-8"):
    resp = MagicMock()
    resp.url = url
    resp.status_code = status_code
    resp.encoding = encoding
    resp.raw.read.return_value = body
    resp.close = MagicMock()
    return resp


class TestCrawlWebsite:
    @patch("core.crawler.requests.Session")
    def test_unreachable_domain_fails_closed(self, mock_session_cls):
        session = MagicMock()
        session.get.side_effect = requests.ConnectionError("refused")
        mock_session_cls.return_value = session

        snap = crawl_website("nowhere.example")

        assert snap.reachable is False
        assert snap.content_hash is None

    @patch("core.crawler.requests.Session")
    def test_reachable_page_computes_content_hash(self, mock_session_cls):
        session = MagicMock()
        session.get.return_value = _mock_response(
            "https://acme.example/", body=b"<html><body>Welcome to Acme</body></html>"
        )
        mock_session_cls.return_value = session

        snap = crawl_website("acme.example")

        assert snap.reachable is True
        assert snap.status_code == 200
        assert snap.content_hash is not None
        assert "Welcome to Acme" in snap.text_snippet

    @patch("core.crawler.requests.Session")
    def test_same_content_produces_same_hash(self, mock_session_cls):
        session = MagicMock()
        session.get.return_value = _mock_response(
            "https://acme.example/", body=b"<html><body>Same content</body></html>"
        )
        mock_session_cls.return_value = session

        snap1 = crawl_website("acme.example")
        snap2 = crawl_website("acme.example")

        assert snap1.content_hash == snap2.content_hash

    @patch("core.crawler.requests.Session")
    def test_form_detection(self, mock_session_cls):
        session = MagicMock()
        session.get.return_value = _mock_response(
            "https://phishy.example/",
            body=b"<html><body><form><input type='password'></form></body></html>",
        )
        mock_session_cls.return_value = session

        snap = crawl_website("phishy.example")

        assert snap.has_forms is True
        assert snap.form_count == 1
        assert snap.has_password_field is True

    @patch("core.crawler.requests.Session")
    def test_no_forms_on_plain_page(self, mock_session_cls):
        session = MagicMock()
        session.get.return_value = _mock_response(
            "https://plain.example/", body=b"<html><body>Just text</body></html>"
        )
        mock_session_cls.return_value = session

        snap = crawl_website("plain.example")

        assert snap.has_forms is False
        assert snap.form_count == 0
        assert snap.has_password_field is False

    @patch("core.crawler.requests.Session")
    def test_cross_domain_redirect_is_flagged(self, mock_session_cls):
        session = MagicMock()
        session.get.return_value = _mock_response("https://totally-different.example/")
        mock_session_cls.return_value = session

        snap = crawl_website("original-domain.example")

        assert snap.redirect_target == "https://totally-different.example/"

    @patch("core.crawler.requests.Session")
    def test_www_prefix_is_not_treated_as_a_redirect(self, mock_session_cls):
        """apex -> www is the single most common non-event; must not be
        flagged as a redirect incident."""
        session = MagicMock()
        session.get.return_value = _mock_response("https://www.acme.example/")
        mock_session_cls.return_value = session

        snap = crawl_website("acme.example")

        assert snap.redirect_target is None

    @patch("core.crawler.requests.Session")
    def test_read_failure_after_connect_fails_closed(self, mock_session_cls):
        session = MagicMock()
        response = MagicMock()
        response.url = "https://acme.example/"
        response.status_code = 200
        response.raw.read.side_effect = OSError("connection reset mid-read")
        session.get.return_value = response
        mock_session_cls.return_value = session

        snap = crawl_website("acme.example")

        assert snap.reachable is False
        assert snap.status_code == 200  # we know it connected, just couldn't read the body


class TestCrawlWebsiteSpaDetection:
    @patch("core.crawler.requests.Session")
    def test_flags_a_react_style_spa_shell(self, mock_session_cls):
        body = b"""<html><head></head><body>
        <noscript>You need to enable JavaScript to run this app.</noscript>
        <div id="root"></div>
        <script src="/static/js/main.abc123.chunk.js"></script>
        </body></html>"""
        session = MagicMock()
        session.get.return_value = _mock_response("https://spa.example/", body=body)
        mock_session_cls.return_value = session

        snap = crawl_website("spa.example")

        assert snap.is_spa is True
        assert "noscript_fallback_text" in snap.spa_signals
        assert "root_mount:root" in snap.spa_signals

    @patch("core.crawler.requests.Session")
    def test_does_not_flag_an_ordinary_server_rendered_page(self, mock_session_cls):
        body = (
            b"<html><body><h1>Welcome</h1><p>"
            + b"This is a perfectly ordinary server-rendered page with real content. " * 5
            + b"</p></body></html>"
        )
        session = MagicMock()
        session.get.return_value = _mock_response("https://normal.example/", body=body)
        mock_session_cls.return_value = session

        snap = crawl_website("normal.example")

        assert snap.is_spa is False
        assert snap.spa_signals == ()


class TestWebsiteSnapshotSerialization:
    def test_round_trips_through_dict(self):
        from core.crawler import WebsiteSnapshot

        original = WebsiteSnapshot(
            reachable=True,
            status_code=200,
            final_url="https://acme.example/",
            content_hash="abc123",
            has_forms=True,
            form_count=2,
            has_password_field=True,
            redirect_target=None,
            text_snippet="hello",
            is_spa=True,
            spa_signals=("root_mount:root",),
        )

        restored = WebsiteSnapshot.from_dict(original.to_dict())

        assert restored == original

    def test_from_empty_dict_is_unreachable_default(self):
        from core.crawler import WebsiteSnapshot

        assert WebsiteSnapshot.from_dict(None) == WebsiteSnapshot()
        assert WebsiteSnapshot.from_dict({}) == WebsiteSnapshot()
