"""Integration tests against a real Postgres for sync_site_graph/
list_site_graph — same discipline as test_storage_postgres.py: no
mocking, since the composite-FK-to-findings relationship (crawled_pages/
page_links -> findings(domain, brand_id)) is exactly the kind of detail
worth getting right against a real schema.
"""

import uuid

import pytest

from adapters.storage_postgres import list_site_graph, sync_site_graph, upsert_finding
from shared.db import SessionLocal
from shared.models import Brand, CrawledPage, Finding, PageLink, Tenant


@pytest.fixture
def session():
    s = SessionLocal()
    yield s
    s.rollback()
    s.close()


@pytest.fixture
def tenant_brand_finding(session):
    tenant = Tenant(name=f"Test Tenant {uuid.uuid4()}", plan_id="free")
    session.add(tenant)
    session.flush()
    brand = Brand(
        tenant_id=tenant.tenant_id, name="testbrand", keywords=[], tlds=["com"], variant_rules=[]
    )
    session.add(brand)
    session.flush()
    # crawled_pages/page_links composite-FK to findings(domain, brand_id)
    # — a finding row has to exist first, same as finding_events.
    upsert_finding(
        session,
        brand_id=brand.brand_id,
        domain="squat.com",
        source="generated",
        status="registered",
    )
    session.commit()
    yield tenant, brand
    session.query(PageLink).filter_by(brand_id=brand.brand_id).delete()
    session.query(CrawledPage).filter_by(brand_id=brand.brand_id).delete()
    session.query(Finding).filter_by(brand_id=brand.brand_id).delete()
    session.query(Brand).filter_by(brand_id=brand.brand_id).delete()
    session.query(Tenant).filter_by(tenant_id=tenant.tenant_id).delete()
    session.commit()


_PAGE = {
    "url": "https://squat.com/",
    "status_code": 200,
    "content_hash": "h1",
    "last_modified": "Mon, 01 Jan 2026 00:00:00 GMT",
    "etag": '"abc"',
    "title": "Home",
    "has_forms": False,
    "form_count": 0,
    "has_password_field": False,
}
_LINK = {
    "from_url": "https://squat.com/",
    "to_url": "https://squat.com/about",
    "is_external": False,
}


def _sync(session, brand, pages=(), links=()):
    sync_site_graph(
        session, brand_id=brand.brand_id, domain="squat.com", pages=list(pages), links=list(links)
    )
    session.commit()


class TestSyncSiteGraph:
    def test_first_sync_inserts_pages_and_links(self, session, tenant_brand_finding):
        _, brand = tenant_brand_finding

        _sync(session, brand, pages=[_PAGE], links=[_LINK])

        pages, links = list_site_graph(session, brand_id=brand.brand_id, domain="squat.com")
        assert len(pages) == 1
        assert pages[0].url == "https://squat.com/"
        assert pages[0].content_hash == "h1"
        assert len(links) == 1
        assert links[0].to_url == "https://squat.com/about"

    def test_second_sync_updates_existing_page_in_place(self, session, tenant_brand_finding):
        _, brand = tenant_brand_finding
        _sync(session, brand, pages=[_PAGE])

        changed_page = {**_PAGE, "content_hash": "h2", "has_forms": True, "form_count": 1}
        _sync(session, brand, pages=[changed_page])

        pages, _ = list_site_graph(session, brand_id=brand.brand_id, domain="squat.com")
        assert len(pages) == 1  # updated in place, not duplicated
        assert pages[0].content_hash == "h2"
        assert pages[0].has_forms is True

    def test_second_sync_does_not_duplicate_an_existing_link(self, session, tenant_brand_finding):
        _, brand = tenant_brand_finding
        _sync(session, brand, links=[_LINK])
        _sync(session, brand, links=[_LINK])

        _, links = list_site_graph(session, brand_id=brand.brand_id, domain="squat.com")
        assert len(links) == 1
