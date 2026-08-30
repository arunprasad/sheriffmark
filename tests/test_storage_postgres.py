"""Integration tests against a real DB (SQLite by default, Postgres if
DATABASE_URL is pointed there — see shared/config.py) — unlike everything
else in core/ and worker/pipeline.py's own tests, these deliberately do
NOT mock the DB, since storage_postgres.py's whole job is getting the
SQLAlchemy details (composite-key upsert, eager loading) right. The
module name predates the SQLite default; nothing in it is actually
Postgres-specific SQL.

Requires DATABASE_URL pointing at a real, migrated database — the
SQLite default needs nothing further; both are run in GitLab CI (see
.gitlab-ci.yml's test:sqlite/test:postgres jobs). Each test creates and
tears down its own tenant/brand rows so it doesn't collide with
worker/seed.py's fixture data or other tests.
"""

import uuid

import pytest

from adapters.storage_postgres import get_active_tenants, update_ct_cursor, upsert_finding
from shared.db import SessionLocal
from shared.models import Brand, Finding, Tenant


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
        active=True,
    )
    session.add(brand)
    session.flush()
    yield tenant, brand
    session.query(Finding).filter_by(brand_id=brand.brand_id).delete()
    session.query(Brand).filter_by(brand_id=brand.brand_id).delete()
    session.query(Tenant).filter_by(tenant_id=tenant.tenant_id).delete()
    session.commit()


class TestUpsertFinding:
    def test_first_call_creates_new_finding(self, session, tenant_and_brand):
        _, brand = tenant_and_brand

        finding, is_new = upsert_finding(
            session,
            brand_id=brand.brand_id,
            domain="squat.com",
            source="generated",
            status="registered",
            risk_score=50,
            risk_factors=["edit_distance<=1"],
        )
        session.commit()

        assert is_new is True
        assert finding.first_seen is not None

    def test_second_call_updates_in_place_without_new_first_seen(
        self, session, tenant_and_brand
    ):
        _, brand = tenant_and_brand

        first, _ = upsert_finding(
            session,
            brand_id=brand.brand_id,
            domain="squat.com",
            source="generated",
            status="registered",
            risk_score=50,
        )
        session.commit()
        original_first_seen = first.first_seen

        second, is_new = upsert_finding(
            session,
            brand_id=brand.brand_id,
            domain="squat.com",
            source="generated",
            status="registered",
            risk_score=80,
        )
        session.commit()

        assert is_new is False
        assert second.first_seen == original_first_seen
        assert second.risk_score == 80

    def test_same_domain_different_brand_does_not_collide(self, session, tenant_and_brand):
        """The exact bug the composite PK fix exists to prevent."""
        _, brand_a = tenant_and_brand

        other_tenant = Tenant(name=f"Other Tenant {uuid.uuid4()}", plan_id="free")
        session.add(other_tenant)
        session.flush()
        brand_b = Brand(
            tenant_id=other_tenant.tenant_id,
            name="otherbrand",
            keywords=[],
            tlds=["com"],
            variant_rules=[],
            active=True,
        )
        session.add(brand_b)
        session.flush()

        try:
            _, is_new_a = upsert_finding(
                session,
                brand_id=brand_a.brand_id,
                domain="shared-name.com",
                source="generated",
                status="registered",
            )
            _, is_new_b = upsert_finding(
                session,
                brand_id=brand_b.brand_id,
                domain="shared-name.com",
                source="generated",
                status="registered",
            )
            session.commit()

            assert is_new_a is True
            assert is_new_b is True  # not swallowed as "already exists"

            count = (
                session.query(Finding)
                .filter_by(domain="shared-name.com")
                .count()
            )
            assert count == 2
        finally:
            session.query(Finding).filter_by(domain="shared-name.com").delete()
            session.query(Brand).filter_by(brand_id=brand_b.brand_id).delete()
            session.query(Tenant).filter_by(tenant_id=other_tenant.tenant_id).delete()
            session.commit()

    def test_screenshot_is_stored_on_first_insert(self, session, tenant_and_brand):
        _, brand = tenant_and_brand

        finding, _ = upsert_finding(
            session,
            brand_id=brand.brand_id,
            domain="squat.com",
            source="generated",
            status="registered",
            screenshot_data=b"fake-png-bytes",
            screenshot_content_type="image/png",
        )
        session.commit()

        assert finding.screenshot_data == b"fake-png-bytes"
        assert finding.screenshot_content_type == "image/png"
        assert finding.screenshot_captured_at is not None

    def test_screenshot_none_does_not_wipe_a_previously_stored_one(
        self, session, tenant_and_brand
    ):
        """Screenshot capture is gated (worker/pipeline.py) — most runs
        pass screenshot_data=None because nothing changed. That must
        not blank out a real screenshot captured on an earlier run."""
        _, brand = tenant_and_brand

        upsert_finding(
            session,
            brand_id=brand.brand_id,
            domain="squat.com",
            source="generated",
            status="registered",
            screenshot_data=b"fake-png-bytes",
            screenshot_content_type="image/png",
        )
        session.commit()

        finding, _ = upsert_finding(
            session,
            brand_id=brand.brand_id,
            domain="squat.com",
            source="generated",
            status="registered",
        )
        session.commit()

        assert finding.screenshot_data == b"fake-png-bytes"

    def test_abuse_email_is_stored_on_first_insert(self, session, tenant_and_brand):
        _, brand = tenant_and_brand

        finding, _ = upsert_finding(
            session,
            brand_id=brand.brand_id,
            domain="squat.com",
            source="generated",
            status="registered",
            abuse_email="abuse@registrar.test",
        )
        session.commit()

        assert finding.abuse_email == "abuse@registrar.test"

    def test_abuse_email_none_does_not_wipe_a_previously_recorded_one(
        self, session, tenant_and_brand
    ):
        """The CT path never resolves an abuse contact (no RDAP call on
        that path) — its abuse_email=None must not blank out a real
        value a different source (RDAP, via the generated path)
        recorded earlier for the same finding."""
        _, brand = tenant_and_brand

        upsert_finding(
            session,
            brand_id=brand.brand_id,
            domain="squat.com",
            source="generated",
            status="registered",
            abuse_email="abuse@registrar.test",
        )
        session.commit()

        finding, _ = upsert_finding(
            session,
            brand_id=brand.brand_id,
            domain="squat.com",
            source="ct",
            status="registered",
            abuse_email=None,
        )
        session.commit()

        assert finding.abuse_email == "abuse@registrar.test"


class TestGetActiveTenants:
    def test_tenant_with_only_inactive_brands_is_excluded(self, session, tenant_and_brand):
        tenant, brand = tenant_and_brand
        brand.active = False
        session.commit()

        active = get_active_tenants(session)

        assert tenant.tenant_id not in [t.tenant_id for t in active]

    def test_tenant_with_active_brand_is_included_with_brands_loaded(
        self, session, tenant_and_brand
    ):
        tenant, brand = tenant_and_brand
        session.commit()

        active = get_active_tenants(session)
        match = next((t for t in active if t.tenant_id == tenant.tenant_id), None)

        assert match is not None
        assert [b.brand_id for b in match.brands] == [brand.brand_id]


class TestUpdateCtCursor:
    def test_sets_and_persists_cursor(self, session, tenant_and_brand):
        _, brand = tenant_and_brand

        update_ct_cursor(session, brand, 12345)
        session.commit()

        reloaded = session.get(Brand, brand.brand_id)
        assert reloaded.ct_last_cert_id == 12345
