"""Site graph acquisition — runs core/site_spider.py's Scrapy spider as a
subprocess and returns its structured result. Subprocess, not an
in-process Scrapy call: Scrapy's Twisted reactor can only be started
once per process, and the worker crawls many domains sequentially
within one long-lived process (see core/site_spider.py's module
docstring for the full reasoning).

Fails closed like every other core/ module: any failure (crawl error,
timeout, malformed output) returns an empty SiteGraph, never an
exception — most candidate domains are unregistered or parked with
nothing behind them, so an empty result is the expected common case.
"""

import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

# Generous relative to the spider's own DOWNLOAD_TIMEOUT (10s) x up to
# MAX_PAGES (25) pages at CONCURRENT_REQUESTS=4 — bounds the worst case
# without cutting off a normal, if slow, small crawl.
DEFAULT_TIMEOUT = 90.0


@dataclass(frozen=True)
class PageRecord:
    url: str
    status_code: int | None
    content_hash: str | None
    last_modified: str | None
    etag: str | None
    title: str | None
    has_forms: bool
    form_count: int
    has_password_field: bool
    is_spa: bool = False
    spa_signals: tuple[str, ...] = ()


@dataclass(frozen=True)
class LinkRecord:
    from_url: str
    to_url: str
    is_external: bool


@dataclass(frozen=True)
class SiteGraph:
    pages: tuple[PageRecord, ...] = ()
    links: tuple[LinkRecord, ...] = ()


def crawl_site_graph(domain: str, timeout: float = DEFAULT_TIMEOUT) -> SiteGraph:
    fd, out_path_str = tempfile.mkstemp(suffix=".json", prefix="site-graph-")
    os.close(fd)
    out_path = Path(out_path_str)
    try:
        subprocess.run(
            [sys.executable, "-m", "core.site_spider", domain, str(out_path)],
            timeout=timeout,
            capture_output=True,
            check=False,
        )
        if not out_path.exists():
            return SiteGraph()
        with out_path.open() as f:
            data = json.load(f)
    except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError):
        return SiteGraph()
    finally:
        out_path.unlink(missing_ok=True)

    pages = tuple(
        PageRecord(**{**p, "spa_signals": tuple(p.get("spa_signals", ()))})
        for p in data.get("pages", [])
    )
    links = tuple(LinkRecord(**link) for link in data.get("links", []))
    return SiteGraph(pages=pages, links=links)
