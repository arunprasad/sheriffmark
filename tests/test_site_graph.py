import json
import subprocess
from unittest.mock import patch

from core.site_graph import LinkRecord, PageRecord, SiteGraph, crawl_site_graph


def _fake_subprocess_run_writing(payload):
    """Returns a function that mimics subprocess.run's side effect of
    core/site_spider.py writing its JSON output to the out_path arg."""

    def _run(cmd, timeout, capture_output, check):
        out_path = cmd[-1]
        with open(out_path, "w") as f:
            json.dump(payload, f)
        return subprocess.CompletedProcess(cmd, 0)

    return _run


class TestCrawlSiteGraph:
    def test_parses_pages_and_links_from_subprocess_output(self):
        payload = {
            "pages": [
                {
                    "url": "https://example.com/",
                    "status_code": 200,
                    "content_hash": "h1",
                    "last_modified": "Mon, 01 Jan 2026 00:00:00 GMT",
                    "etag": '"abc"',
                    "title": "Example",
                    "has_forms": False,
                    "form_count": 0,
                    "has_password_field": False,
                }
            ],
            "links": [
                {
                    "from_url": "https://example.com/",
                    "to_url": "https://example.com/about",
                    "is_external": False,
                }
            ],
        }
        run_mock = _fake_subprocess_run_writing(payload)
        with patch("core.site_graph.subprocess.run", side_effect=run_mock):
            graph = crawl_site_graph("example.com")

        assert graph.pages == (
            PageRecord(
                url="https://example.com/",
                status_code=200,
                content_hash="h1",
                last_modified="Mon, 01 Jan 2026 00:00:00 GMT",
                etag='"abc"',
                title="Example",
                has_forms=False,
                form_count=0,
                has_password_field=False,
            ),
        )
        assert graph.links == (
            LinkRecord(
                from_url="https://example.com/",
                to_url="https://example.com/about",
                is_external=False,
            ),
        )

    def test_parses_spa_flag_and_signals_as_a_tuple(self):
        payload = {
            "pages": [
                {
                    "url": "https://spa.example/",
                    "status_code": 200,
                    "content_hash": "h1",
                    "last_modified": None,
                    "etag": None,
                    "title": None,
                    "has_forms": False,
                    "form_count": 0,
                    "has_password_field": False,
                    "is_spa": True,
                    "spa_signals": ["root_mount:root", "noscript_fallback_text"],
                }
            ],
            "links": [],
        }
        run_mock = _fake_subprocess_run_writing(payload)
        with patch("core.site_graph.subprocess.run", side_effect=run_mock):
            graph = crawl_site_graph("spa.example")

        assert graph.pages[0].is_spa is True
        assert graph.pages[0].spa_signals == ("root_mount:root", "noscript_fallback_text")

    def test_timeout_returns_empty_graph(self):
        with patch(
            "core.site_graph.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="x", timeout=90),
        ):
            graph = crawl_site_graph("example.com")

        assert graph == SiteGraph()

    def test_malformed_output_returns_empty_graph(self):
        def _run(cmd, timeout, capture_output, check):
            out_path = cmd[-1]
            with open(out_path, "w") as f:
                f.write("not json")
            return subprocess.CompletedProcess(cmd, 0)

        with patch("core.site_graph.subprocess.run", side_effect=_run):
            graph = crawl_site_graph("example.com")

        assert graph == SiteGraph()

    def test_empty_crawl_result_is_an_empty_graph(self):
        with patch(
            "core.site_graph.subprocess.run",
            side_effect=_fake_subprocess_run_writing({"pages": [], "links": []}),
        ):
            graph = crawl_site_graph("example.com")

        assert graph == SiteGraph()
