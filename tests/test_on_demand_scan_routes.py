"""API-level tests for ad hoc on-demand scan requests. FastAPI's
TestClient runs BackgroundTasks synchronously before `.post()` returns,
so by the time a request finishes, the (mocked) background job has
already run — these tests rely on that to assert post-completion state
without polling.

`run_on_demand_scan` itself is mocked at the routes module's import
site throughout — its own behavior (registration/DNS acquisition,
_record_finding wiring, rate-limit handling) is covered by
tests/test_pipeline.py's TestRunOnDemandScan. These tests are about the
request/job-tracking plumbing: normalization, the per-request domain
cap, tenant/brand scoping, and the completed/failed status mapping.
"""

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from core.registration import RegistrationStatus
from shared.db import SessionLocal, get_session
from shared.models import Brand, OnDemandScanRequest, Tenant, User
from web.api.auth import AuthenticatedUser
from web.api.main import app
from web.api.tenancy import get_current_tenant, get_or_create_tenant

TENANT_NAME = "on-demand-scan-test@example.com"


@pytest.fixture
def session():
    s = SessionLocal()
    yield s
    s.rollback()
    s.close()


@pytest.fixture
def external_id():
    return f"test-on-demand-{uuid.uuid4()}"


@pytest.fixture
def client(session, external_id):
    fake_user = AuthenticatedUser(external_id=external_id, email=TENANT_NAME)

    def override_get_session():
        yield session

    def override_get_current_tenant():
        return get_or_create_tenant(session, fake_user)

    app.dependency_overrides[get_session] = override_get_session
    app.dependency_overrides[get_current_tenant] = override_get_current_tenant

    yield TestClient(app)

    app.dependency_overrides.clear()
    tenant_ids = session.query(Tenant.tenant_id).filter_by(name=TENANT_NAME)
    brand_ids = session.query(Brand.brand_id).filter(Brand.tenant_id.in_(tenant_ids))
    session.query(OnDemandScanRequest).filter(
        OnDemandScanRequest.brand_id.in_(brand_ids)
    ).delete(synchronize_session=False)
    session.query(Brand).filter(Brand.tenant_id.in_(tenant_ids)).delete(synchronize_session=False)
    session.query(User).filter_by(external_id=external_id).delete()
    session.query(Tenant).filter_by(name=TENANT_NAME).delete()
    session.commit()


@pytest.fixture
def brand(client, session, external_id):
    """Ensures the tenant exists (via one client call) then creates a
    brand for it directly — on-demand scans are brand-scoped."""
    client.get("/api/brands")
    tenant = get_or_create_tenant(
        session, AuthenticatedUser(external_id=external_id, email=TENANT_NAME)
    )
    b = Brand(
        tenant_id=tenant.tenant_id,
        name="Acme",
        keywords=["acme"],
        tlds=["com"],
        variant_rules=[],
        custom_domains=[],
        owned_domains=[],
        active=True,
    )
    session.add(b)
    session.commit()
    return b


class TestCreateOnDemandScans:
    @patch(
        "web.api.routes.on_demand_scans.run_on_demand_scan",
        return_value=RegistrationStatus(status="registered", registrar="Example Registrar"),
    )
    def test_creates_and_completes_via_background_task(self, _mock_run, client, brand):
        resp = client.post(
            f"/api/brands/{brand.brand_id}/on-demand-scans", json={"domains": ["Taken.Example"]}
        )

        assert resp.status_code == 202
        body = resp.json()[0]
        assert body["domain"] == "taken.example"  # normalized
        assert body["status"] == "pending"  # snapshot taken before the background task ran

        follow_up = client.get(f"/api/brands/{brand.brand_id}/on-demand-scans/{body['id']}")
        assert follow_up.status_code == 200
        assert follow_up.json()["status"] == "completed"

    @patch(
        "web.api.routes.on_demand_scans.run_on_demand_scan", side_effect=RuntimeError("boom")
    )
    def test_unexpected_failure_marks_request_failed(self, _mock_run, client, brand):
        resp = client.post(
            f"/api/brands/{brand.brand_id}/on-demand-scans", json={"domains": ["nope.example"]}
        )
        request_id = resp.json()[0]["id"]

        follow_up = client.get(f"/api/brands/{brand.brand_id}/on-demand-scans/{request_id}")

        assert follow_up.json()["status"] == "failed"
        assert "boom" in follow_up.json()["error"]

    @patch(
        "web.api.routes.on_demand_scans.run_on_demand_scan",
        return_value=RegistrationStatus(status="unknown", rate_limited=True),
    )
    def test_rate_limited_result_marks_request_failed_with_a_clear_reason(
        self, _mock_run, client, brand
    ):
        resp = client.post(
            f"/api/brands/{brand.brand_id}/on-demand-scans", json={"domains": ["nope.example"]}
        )
        request_id = resp.json()[0]["id"]

        follow_up = client.get(f"/api/brands/{brand.brand_id}/on-demand-scans/{request_id}")

        assert follow_up.json()["status"] == "failed"
        assert "rate-limited" in follow_up.json()["error"]

    @patch(
        "web.api.routes.on_demand_scans.run_on_demand_scan",
        return_value=RegistrationStatus(status="unknown"),
    )
    def test_genuinely_unknown_result_marks_request_failed(self, _mock_run, client, brand):
        resp = client.post(
            f"/api/brands/{brand.brand_id}/on-demand-scans", json={"domains": ["nope.example"]}
        )
        request_id = resp.json()[0]["id"]

        follow_up = client.get(f"/api/brands/{brand.brand_id}/on-demand-scans/{request_id}")

        assert follow_up.json()["status"] == "failed"

    def test_rejects_more_than_the_per_request_cap(self, client, brand):
        resp = client.post(
            f"/api/brands/{brand.brand_id}/on-demand-scans",
            json={"domains": [f"d{i}.example" for i in range(6)]},
        )
        assert resp.status_code == 422

    def test_rejects_empty_domain_list(self, client, brand):
        resp = client.post(f"/api/brands/{brand.brand_id}/on-demand-scans", json={"domains": []})
        assert resp.status_code == 422

    def test_rejects_malformed_domain(self, client, brand):
        resp = client.post(
            f"/api/brands/{brand.brand_id}/on-demand-scans", json={"domains": ["not a domain"]}
        )
        assert resp.status_code == 422

    def test_unknown_brand_is_404(self, client):
        resp = client.post(
            f"/api/brands/{uuid.uuid4()}/on-demand-scans", json={"domains": ["a.example"]}
        )
        assert resp.status_code == 404

    @patch(
        "web.api.routes.on_demand_scans.run_on_demand_scan",
        return_value=RegistrationStatus(status="registered"),
    )
    def test_accepts_a_few_domains_at_once(self, _mock_run, client, brand):
        resp = client.post(
            f"/api/brands/{brand.brand_id}/on-demand-scans",
            json={"domains": ["a.example", "b.example", "c.example"]},
        )
        assert resp.status_code == 202
        assert len(resp.json()) == 3


class TestGetOnDemandScan:
    def test_unknown_id_is_404(self, client, brand):
        resp = client.get(f"/api/brands/{brand.brand_id}/on-demand-scans/{uuid.uuid4()}")
        assert resp.status_code == 404

    def test_stale_running_request_is_reported_failed(self, client, session, brand):
        request = OnDemandScanRequest(
            brand_id=brand.brand_id, domain="stuck.example", status="running"
        )
        session.add(request)
        session.commit()
        # Simulate a process restart mid-job: back-date updated_at past
        # the staleness threshold directly in the DB (the ORM's
        # onupdate=func.now() would otherwise stamp "now" on any save).
        session.execute(
            OnDemandScanRequest.__table__.update()
            .where(OnDemandScanRequest.id == request.id)
            .values(updated_at=datetime.now(UTC) - timedelta(minutes=30))
        )
        session.commit()
        # expire_on_commit=False means the ORM-loaded `request` object
        # doesn't know about the raw SQL update above — force a refetch
        # so the route's own session.get() sees the back-dated value.
        session.expire(request)

        resp = client.get(f"/api/brands/{brand.brand_id}/on-demand-scans/{request.id}")

        assert resp.json()["status"] == "failed"
        assert "restart" in resp.json()["error"].lower()


class TestCrossTenantAccess:
    def test_another_tenants_brand_is_404_not_leaked(self, client, session):
        other_tenant = Tenant(name=f"other-{uuid.uuid4()}", plan_id="free")
        session.add(other_tenant)
        session.flush()
        other_brand = Brand(
            tenant_id=other_tenant.tenant_id,
            name="Other",
            keywords=[],
            tlds=["com"],
            variant_rules=[],
            custom_domains=[],
            owned_domains=[],
            active=True,
        )
        session.add(other_brand)
        session.commit()
        try:
            resp = client.post(
                f"/api/brands/{other_brand.brand_id}/on-demand-scans",
                json={"domains": ["a.example"]},
            )
            assert resp.status_code == 404
        finally:
            session.query(Brand).filter_by(brand_id=other_brand.brand_id).delete()
            session.query(Tenant).filter_by(tenant_id=other_tenant.tenant_id).delete()
            session.commit()


class TestListOnDemandScans:
    @patch(
        "web.api.routes.on_demand_scans.run_on_demand_scan",
        return_value=RegistrationStatus(status="registered"),
    )
    def test_lists_newest_first(self, _mock_run, client, brand):
        client.post(
            f"/api/brands/{brand.brand_id}/on-demand-scans", json={"domains": ["first.example"]}
        )
        client.post(
            f"/api/brands/{brand.brand_id}/on-demand-scans", json={"domains": ["second.example"]}
        )

        resp = client.get(f"/api/brands/{brand.brand_id}/on-demand-scans")

        domains = [r["domain"] for r in resp.json()]
        assert domains == ["second.example", "first.example"]
