"""Scrapy site-graph spider — run as a standalone subprocess
(`python -m core.site_spider <domain> <out_path>`), never imported and
run in-process. Scrapy's Twisted reactor can only start once per
process, and the worker crawls many domains one after another within a
single long-lived process — see core/site_graph.py's `crawl_site_graph`,
the actual entry point every caller uses.

Deliberately bounded small: depth 2, ~25 pages. This runs once per
registered finding per daily scan; an unbounded crawl here would turn a
scan of hundreds of monitored domains into an open-ended job. Extracts
structure (content hash, the server's own Last-Modified/ETag, forms,
links) — never the page body itself, see shared/models.py's
`CrawledPage` docstring for why.
"""

import hashlib
import json
import sys

import scrapy
from bs4 import BeautifulSoup
from scrapy.crawler import CrawlerProcess

from core.crawler import _registrable_host
from core.spa_detection import detect_spa

MAX_PAGES = 25
DEPTH_LIMIT = 2
USER_AGENT = "SheriffMarkBot/1.0 (+https://github.com/; domain-protection monitoring)"


class SiteGraphSpider(scrapy.Spider):
    name = "site_graph"

    custom_settings = {
        "USER_AGENT": USER_AGENT,
        "ROBOTSTXT_OBEY": True,
        "DEPTH_LIMIT": DEPTH_LIMIT,
        "CLOSESPIDER_PAGECOUNT": MAX_PAGES,
        "CONCURRENT_REQUESTS": 4,
        "DOWNLOAD_TIMEOUT": 10,
        # Retries would multiply worst-case runtime across up to 25 pages
        # for what's already a best-effort, fail-closed acquisition —
        # a domain that times out once just yields fewer pages this run,
        # not a blocked pipeline.
        "RETRY_ENABLED": False,
        "AUTOTHROTTLE_ENABLED": True,
        "AUTOTHROTTLE_START_DELAY": 0.5,
        "LOG_ENABLED": False,
        "TELNETCONSOLE_ENABLED": False,
    }

    def __init__(self, domain: str, out_path: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.domain = domain
        self.allowed_domains = [domain]
        self.out_path = out_path
        self.pages: list[dict] = []
        self.links: list[dict] = []
        self._seen_urls: set[str] = set()
        self._base_host = _registrable_host(f"https://{domain}/")

    async def start(self):
        # Scrapy >=2.13's async entry point (start_requests() alone is
        # silently never called on these versions) — see
        # https://docs.scrapy.org/en/latest/topics/request-response.html#start-requests.
        yield scrapy.Request(
            f"https://{self.domain}/",
            callback=self.parse,
            errback=self._try_http,
            dont_filter=True,
            meta={"depth": 0},
        )

    def _try_http(self, failure):
        yield scrapy.Request(
            f"http://{self.domain}/",
            callback=self.parse,
            errback=self._on_unreachable,
            dont_filter=True,
            meta={"depth": 0},
        )

    def _on_unreachable(self, failure):
        return None

    def parse(self, response):
        content_type = response.headers.get("Content-Type", b"").decode(errors="ignore")
        if "text/html" not in content_type:
            return

        if response.url in self._seen_urls or len(self.pages) >= MAX_PAGES:
            return
        self._seen_urls.add(response.url)

        try:
            soup = BeautifulSoup(response.text, "html.parser")
        except Exception:
            soup = None

        forms = soup.find_all("form") if soup else []
        has_password_field = bool(soup and soup.find("input", attrs={"type": "password"}))
        title = soup.title.get_text(strip=True) if soup and soup.title else None
        visible_text = soup.get_text(separator=" ", strip=True) if soup else response.text
        spa_signal = detect_spa(response.text, visible_text)

        self.pages.append(
            {
                "url": response.url,
                "status_code": response.status,
                "content_hash": hashlib.sha256(response.body).hexdigest(),
                "last_modified": response.headers.get("Last-Modified", b"").decode(errors="ignore")
                or None,
                "etag": response.headers.get("ETag", b"").decode(errors="ignore") or None,
                "title": title,
                "has_forms": len(forms) > 0,
                "form_count": len(forms),
                "has_password_field": has_password_field,
                "is_spa": spa_signal.is_spa,
                "spa_signals": list(spa_signal.reasons),
            }
        )

        if not soup or response.meta.get("depth", 0) >= DEPTH_LIMIT:
            return

        seen_on_page = set()
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            abs_url = response.urljoin(href).split("#")[0]
            if abs_url in seen_on_page:
                continue
            seen_on_page.add(abs_url)

            is_external = _registrable_host(abs_url) != self._base_host
            self.links.append(
                {"from_url": response.url, "to_url": abs_url, "is_external": is_external}
            )
            if not is_external and len(self.pages) < MAX_PAGES:
                yield response.follow(abs_url, callback=self.parse)

    def closed(self, reason):
        with open(self.out_path, "w") as f:
            json.dump({"pages": self.pages, "links": self.links}, f)


if __name__ == "__main__":
    _domain, _out_path = sys.argv[1], sys.argv[2]
    _process = CrawlerProcess(settings={"LOG_ENABLED": False, "TELNETCONSOLE_ENABLED": False})
    _process.crawl(SiteGraphSpider, domain=_domain, out_path=_out_path)
    _process.start()
