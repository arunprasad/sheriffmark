"""Integration tests against a real Postgres for the resolution-workflow
storage functions — same discipline as test_storage_postgres.py.
"""

import uuid

import pytest

from adapters.storage_postgres import (
    add_owned_domain,
    count_unresolved_findings,
    list_finding_events,
    set_finding_resolution,
    upsert_finding,
)
from shared.db import SessionLocal
from shared.models import Brand, Finding, FindingEvent, Tenant


@pytest.fixture
def session():
    s = SessionLocal()
    yield s
    s.rollback()
    s.close()


@pytest.fixture
def tenant_and_brand(session):
    tenant = Tenant(name=f"Test Tenant {uuid.uuid4()}", plan_id="free")
    session.add(tenant)
    session.flush()
    brand = Brand(
        tenant_id=tenant.tenant_id,
        name="testbrand",
        keywords=[],
        tlds=["com"],
        variant_rules=[],
        custom_domains=[],
        owned_domains=[],
        active=True,
    )
    session.add(brand)
    session.flush()
    yield tenant, brand
    session.query(FindingEvent).filter_by(brand_id=brand.brand_id).delete()
    session.query(Finding).filter_by(brand_id=brand.brand_id).delete()
    session.query(Brand).filter_by(brand_id=brand.brand_id).delete()
    session.query(Tenant).filter_by(tenant_id=tenant.tenant_id).delete()
    session.commit()


class TestAddOwnedDomain:
    def test_adds_a_new_domain(self, session, tenant_and_brand):
        _, brand = tenant_and_brand

        changed = add_owned_domain(session, brand=brand, domain="acme-shop.com")

        assert changed is True
        assert brand.owned_domains == ["acme-shop.com"]

    def test_already_owned_is_a_no_op(self, session, tenant_and_brand):
        _, brand = tenant_and_brand
        brand.owned_domains = ["acme-shop.com"]

        changed = add_owned_domain(session, brand=brand, domain="acme-shop.com")

        assert changed is False
        assert brand.owned_domains == ["acme-shop.com"]

    def test_removes_it_from_custom_domains_too(self, session, tenant_and_brand):
        _, brand = tenant_and_brand
        brand.custom_domains = ["acme-shop.com"]

        changed = add_owned_domain(session, brand=brand, domain="acme-shop.com")

        assert changed is True
        assert brand.owned_domains == ["acme-shop.com"]
        assert brand.custom_domains == []


class TestCountUnresolvedFindings:
    def test_open_and_resolution_failed_count_as_unresolved(self, session, tenant_and_brand):
        _, brand = tenant_and_brand
        upsert_finding(
            session,
            brand_id=brand.brand_id,
            domain="a.com",
            source="generated",
            status="registered",
        )
        upsert_finding(
            session,
            brand_id=brand.brand_id,
            domain="b.com",
            source="generated",
            status="registered",
        )
        session.commit()
        set_finding_resolution(
            session,
            brand_id=brand.brand_id,
            domain="b.com",
            resolution_status="resolution_failed",
            note=None,
        )

        assert count_unresolved_findings(session, brand_id=brand.brand_id) == 2

    def test_resolved_and_resolved_owned_do_not_count(self, session, tenant_and_brand):
        _, brand = tenant_and_brand
        upsert_finding(
            session,
            brand_id=brand.brand_id,
            domain="a.com",
            source="generated",
            status="registered",
        )
        upsert_finding(
            session,
            brand_id=brand.brand_id,
            domain="b.com",
            source="generated",
            status="registered",
        )
        session.commit()
        set_finding_resolution(
            session,
            brand_id=brand.brand_id,
            domain="a.com",
            resolution_status="resolved",
            note=None,
        )
        set_finding_resolution(
            session,
            brand_id=brand.brand_id,
            domain="b.com",
            resolution_status="resolved_owned",
            note=None,
        )

        assert count_unresolved_findings(session, brand_id=brand.brand_id) == 0

    def test_unregistered_findings_never_count(self, session, tenant_and_brand):
        _, brand = tenant_and_brand
        upsert_finding(
            session,
            brand_id=brand.brand_id,
            domain="a.com",
            source="manual",
            status="unregistered",
        )
        session.commit()

        assert count_unresolved_findings(session, brand_id=brand.brand_id) == 0


class TestSetFindingResolution:
    def test_updates_status_and_note(self, session, tenant_and_brand):
        _, brand = tenant_and_brand
        upsert_finding(
            session,
            brand_id=brand.brand_id,
            domain="a.com",
            source="generated",
            status="registered",
        )
        session.commit()

        finding = set_finding_resolution(
            session,
            brand_id=brand.brand_id,
            domain="a.com",
            resolution_status="resolved",
            note="took it down",
        )

        assert finding.resolution_status == "resolved"
        assert finding.resolution_note == "took it down"

    def test_records_a_matching_finding_event(self, session, tenant_and_brand):
        _, brand = tenant_and_brand
        upsert_finding(
            session,
            brand_id=brand.brand_id,
            domain="a.com",
            source="generated",
            status="registered",
        )
        session.commit()

        set_finding_resolution(
            session,
            brand_id=brand.brand_id,
            domain="a.com",
            resolution_status="resolution_failed",
            note="registrar didn't respond",
        )

        events = list_finding_events(session, brand_id=brand.brand_id, domain="a.com")
        assert events[0].event_type == "resolution_failed"
        assert events[0].details == {"note": "registrar didn't respond"}

    def test_reopen_records_a_reopened_event_not_an_open_event(self, session, tenant_and_brand):
        _, brand = tenant_and_brand
        upsert_finding(
            session,
            brand_id=brand.brand_id,
            domain="a.com",
            source="generated",
            status="registered",
        )
        session.commit()
        set_finding_resolution(
            session,
            brand_id=brand.brand_id,
            domain="a.com",
            resolution_status="resolved",
            note=None,
        )

        set_finding_resolution(
            session,
            brand_id=brand.brand_id,
            domain="a.com",
            resolution_status="open",
            note=None,
        )

        events = list_finding_events(session, brand_id=brand.brand_id, domain="a.com")
        assert events[0].event_type == "reopened"

    def test_unknown_finding_returns_none(self, session, tenant_and_brand):
        _, brand = tenant_and_brand

        result = set_finding_resolution(
            session,
            brand_id=brand.brand_id,
            domain="never-existed.com",
            resolution_status="resolved",
            note=None,
        )

        assert result is None
