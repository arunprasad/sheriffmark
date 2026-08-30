from scrapy.http import HtmlResponse, Request

from core.site_spider import DEPTH_LIMIT, MAX_PAGES, SiteGraphSpider


def _spider(domain="example.com", out_path="/tmp/unused.json"):
    return SiteGraphSpider(domain=domain, out_path=out_path)


def _html_response(url, body, depth=0, content_type="text/html; charset=utf-8"):
    request = Request(url, meta={"depth": depth})
    return HtmlResponse(
        url=url,
        body=body.encode(),
        request=request,
        headers={"Content-Type": content_type},
    )


class TestParse:
    def test_records_a_page_with_forms_and_password_field(self):
        spider = _spider()
        body = """
        <html><head><title>Login</title></head>
        <body><form><input type="password"></form></body></html>
        """
        response = _html_response("https://example.com/", body)

        list(spider.parse(response))

        assert len(spider.pages) == 1
        page = spider.pages[0]
        assert page["url"] == "https://example.com/"
        assert page["title"] == "Login"
        assert page["has_forms"] is True
        assert page["form_count"] == 1
        assert page["has_password_field"] is True
        assert page["content_hash"]  # non-empty hash of the raw body
        assert page["is_spa"] is False

    def test_records_spa_signals_for_a_client_rendered_shell(self):
        spider = _spider()
        body = """
        <html><body>
        <noscript>You need to enable JavaScript to run this app.</noscript>
        <div id="root"></div>
        <script src="/static/js/main.abc123.chunk.js"></script>
        </body></html>
        """
        response = _html_response("https://spa.example/", body)

        list(spider.parse(response))

        page = spider.pages[0]
        assert page["is_spa"] is True
        assert "noscript_fallback_text" in page["spa_signals"]

    def test_non_html_content_type_is_skipped(self):
        spider = _spider()
        response = _html_response(
            "https://example.com/logo.png", "binary", content_type="image/png"
        )

        list(spider.parse(response))

        assert spider.pages == []

    def test_internal_links_are_followed_and_recorded_as_edges(self):
        spider = _spider()
        body = '<html><body><a href="/about">About</a></body></html>'
        response = _html_response("https://example.com/", body, depth=0)

        requests = list(spider.parse(response))

        assert len(requests) == 1
        assert requests[0].url == "https://example.com/about"
        assert spider.links == [
            {
                "from_url": "https://example.com/",
                "to_url": "https://example.com/about",
                "is_external": False,
            }
        ]

    def test_external_links_are_recorded_but_not_followed(self):
        spider = _spider()
        body = '<html><body><a href="https://evil.example/phish">click</a></body></html>'
        response = _html_response("https://example.com/", body, depth=0)

        requests = list(spider.parse(response))

        assert requests == []
        assert spider.links == [
            {
                "from_url": "https://example.com/",
                "to_url": "https://evil.example/phish",
                "is_external": True,
            }
        ]

    def test_www_is_not_treated_as_external(self):
        spider = _spider()
        body = '<html><body><a href="https://www.example.com/x">x</a></body></html>'
        response = _html_response("https://example.com/", body, depth=0)

        list(spider.parse(response))

        assert spider.links[0]["is_external"] is False

    def test_stops_following_links_at_the_depth_limit(self):
        spider = _spider()
        body = '<html><body><a href="/deeper">deeper</a></body></html>'
        response = _html_response("https://example.com/deep", body, depth=DEPTH_LIMIT)

        requests = list(spider.parse(response))

        assert requests == []  # page still recorded, just not followed further
        assert len(spider.pages) == 1

    def test_same_url_is_not_recorded_twice(self):
        spider = _spider()
        body = "<html><body>hi</body></html>"
        response = _html_response("https://example.com/", body)

        list(spider.parse(response))
        list(spider.parse(response))

        assert len(spider.pages) == 1

    def test_stops_recording_pages_past_the_max_page_bound(self):
        spider = _spider()
        spider.pages = [{"url": f"https://example.com/{i}"} for i in range(MAX_PAGES)]
        response = _html_response("https://example.com/one-too-many", "<html></html>")

        list(spider.parse(response))

        assert len(spider.pages) == MAX_PAGES  # unchanged, bound enforced
