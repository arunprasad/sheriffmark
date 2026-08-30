"""API route tests against a real DB. Auth itself is unit-tested in
test_auth.py (mocked JWT verification) — here we override
get_current_tenant to bootstrap a real, disposable tenant per test via
the same get_or_create_tenant path production uses, so route logic
(tenant scoping, limit enforcement, 404-not-403 on cross-tenant access)
is exercised for real rather than mocked away.
"""

import csv
import io
import uuid

import pytest
from fastapi.testclient import TestClient

from shared.db import SessionLocal, get_session
from shared.models import Brand, CrawledPage, Finding, FindingEvent, PageLink, Tenant, User
from web.api.auth import AuthenticatedUser
from web.api.main import app
from web.api.tenancy import get_current_tenant, get_or_create_tenant


@pytest.fixture
def session():
    s = SessionLocal()
    yield s
    s.rollback()
    s.close()


@pytest.fixture
def client(session):
    external_id = f"test-route-{uuid.uuid4()}"
    fake_user = AuthenticatedUser(external_id=external_id, email="route-test@example.com")

    def override_get_session():
        yield session

    def override_get_current_tenant():
        return get_or_create_tenant(session, fake_user)

    app.dependency_overrides[get_session] = override_get_session
    app.dependency_overrides[get_current_tenant] = override_get_current_tenant

    yield TestClient(app)

    app.dependency_overrides.clear()
    session.query(Brand).filter(
        Brand.tenant_id.in_(
            session.query(Tenant.tenant_id).filter_by(name="route-test@example.com")
        )
    ).delete(synchronize_session=False)
    session.query(User).filter_by(external_id=external_id).delete()
    session.query(Tenant).filter_by(name="route-test@example.com").delete()
    session.commit()


class TestBrandRoutes:
    def test_list_starts_empty(self, client):
        resp = client.get("/api/brands")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_create_and_list(self, client):
        resp = client.post(
            "/api/brands", json={"name": "acme", "keywords": ["login"], "tlds": ["com"]}
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["name"] == "acme"
        assert body["active"] is True

        resp = client.get("/api/brands")
        assert len(resp.json()) == 1

    def test_self_hosted_plan_has_no_brand_limit(self, client):
        """OSS conversion: the seeded plan is unlimited by default (no
        billing, no gating) — see migrations/versions/20260823_000000_oss_unlimited_plan.py.
        check_limit's actual cap-enforcement behavior is covered
        separately in tests/test_limits.py using a synthetic capped plan."""
        first = client.post("/api/brands", json={"name": "brand-one"})
        assert first.status_code == 201

        second = client.post("/api/brands", json={"name": "brand-two"})
        assert second.status_code == 201

    def test_delete_own_brand(self, client):
        created = client.post("/api/brands", json={"name": "to-delete"}).json()

        resp = client.delete(f"/api/brands/{created['brand_id']}")
        assert resp.status_code == 204
        assert client.get("/api/brands").json() == []

    def test_delete_nonexistent_brand_is_404(self, client):
        resp = client.delete(f"/api/brands/{uuid.uuid4()}")
        assert resp.status_code == 404

    def test_new_brand_has_empty_custom_domains(self, client):
        brand = client.post("/api/brands", json={"name": "acme"}).json()
        assert brand["custom_domains"] == []

    def test_new_brand_has_empty_owned_domains(self, client):
        brand = client.post("/api/brands", json={"name": "acme"}).json()
        assert brand["owned_domains"] == []

    def test_new_brand_has_no_completed_scan_and_zero_unresolved(self, client):
        brand = client.post("/api/brands", json={"name": "acme"}).json()
        assert brand["last_scan_completed_at"] is None
        assert brand["unresolved_findings_count"] == 0

    def test_list_reports_unresolved_findings_count(self, client, session):
        brand = client.post("/api/brands", json={"name": "acme"}).json()
        brand_id = uuid.UUID(brand["brand_id"])
        finding = Finding(
            domain="acme-login.com", brand_id=brand_id, source="generated", status="registered"
        )
        session.add(finding)
        session.commit()

        try:
            listed = client.get("/api/brands").json()
            assert listed[0]["unresolved_findings_count"] == 1
        finally:
            session.query(Finding).filter_by(brand_id=brand_id).delete()
            session.commit()


class TestUpdateBrand:
    def test_updates_name(self, client):
        brand = client.post("/api/brands", json={"name": "old-name"}).json()

        resp = client.patch(f"/api/brands/{brand['brand_id']}", json={"name": "new-name"})

        assert resp.status_code == 200
        assert resp.json()["name"] == "new-name"

    def test_pause_and_resume(self, client):
        brand = client.post("/api/brands", json={"name": "acme"}).json()

        paused = client.patch(f"/api/brands/{brand['brand_id']}", json={"active": False})
        assert paused.json()["active"] is False

        resumed = client.patch(f"/api/brands/{brand['brand_id']}", json={"active": True})
        assert resumed.json()["active"] is True

    def test_updates_keywords_and_tlds(self, client):
        brand = client.post("/api/brands", json={"name": "acme"}).json()

        resp = client.patch(
            f"/api/brands/{brand['brand_id']}",
            json={"keywords": ["portal"], "tlds": ["net"]},
        )

        body = resp.json()
        assert body["keywords"] == ["portal"]
        assert body["tlds"] == ["net"]

    def test_partial_update_leaves_other_fields_untouched(self, client):
        brand = client.post(
            "/api/brands", json={"name": "acme", "keywords": ["login"], "tlds": ["com"]}
        ).json()

        resp = client.patch(f"/api/brands/{brand['brand_id']}", json={"name": "renamed"})

        body = resp.json()
        assert body["name"] == "renamed"
        assert body["keywords"] == ["login"]
        assert body["tlds"] == ["com"]

    def test_empty_body_is_a_no_op(self, client):
        brand = client.post("/api/brands", json={"name": "acme"}).json()

        resp = client.patch(f"/api/brands/{brand['brand_id']}", json={})

        assert resp.status_code == 200
        assert resp.json()["name"] == "acme"

    def test_nonexistent_brand_is_404(self, client):
        resp = client.patch(f"/api/brands/{uuid.uuid4()}", json={"name": "x"})
        assert resp.status_code == 404

    def test_another_tenants_brand_is_404(self, client, session):
        other_tenant = Tenant(name=f"update-other-{uuid.uuid4()}", plan_id="free")
        session.add(other_tenant)
        session.flush()
        other_brand = Brand(
            tenant_id=other_tenant.tenant_id,
            name="not-yours",
            keywords=[],
            tlds=["com"],
            variant_rules=[],
            custom_domains=[],
            active=True,
        )
        session.add(other_brand)
        session.commit()

        try:
            resp = client.patch(f"/api/brands/{other_brand.brand_id}", json={"name": "hijacked"})
            assert resp.status_code == 404
        finally:
            session.query(Brand).filter_by(brand_id=other_brand.brand_id).delete()
            session.query(Tenant).filter_by(tenant_id=other_tenant.tenant_id).delete()
            session.commit()


class TestCustomDomains:
    def test_add_and_list(self, client):
        brand = client.post("/api/brands", json={"name": "acme"}).json()

        resp = client.post(
            f"/api/brands/{brand['brand_id']}/custom-domains",
            json={"domain": "Acme-Secure-Login.NET"},
        )

        assert resp.status_code == 201
        assert resp.json()["custom_domains"] == ["acme-secure-login.net"]  # normalized

    def test_adding_same_domain_twice_does_not_duplicate(self, client):
        brand = client.post("/api/brands", json={"name": "acme"}).json()
        url = f"/api/brands/{brand['brand_id']}/custom-domains"

        client.post(url, json={"domain": "watched.net"})
        resp = client.post(url, json={"domain": "watched.net"})

        assert resp.json()["custom_domains"] == ["watched.net"]

    def test_invalid_domain_is_422(self, client):
        brand = client.post("/api/brands", json={"name": "acme"}).json()

        resp = client.post(
            f"/api/brands/{brand['brand_id']}/custom-domains",
            json={"domain": "this is not a domain"},
        )

        assert resp.status_code == 422

    def test_remove(self, client):
        brand = client.post("/api/brands", json={"name": "acme"}).json()
        url = f"/api/brands/{brand['brand_id']}/custom-domains"
        client.post(url, json={"domain": "watched.net"})

        resp = client.delete(f"{url}/watched.net")

        assert resp.status_code == 200
        assert resp.json()["custom_domains"] == []

    def test_remove_nonexistent_entry_is_a_no_op_not_an_error(self, client):
        brand = client.post("/api/brands", json={"name": "acme"}).json()

        resp = client.delete(f"/api/brands/{brand['brand_id']}/custom-domains/never-added.net")

        assert resp.status_code == 200
        assert resp.json()["custom_domains"] == []

    def test_add_to_nonexistent_brand_is_404(self, client):
        resp = client.post(
            f"/api/brands/{uuid.uuid4()}/custom-domains", json={"domain": "watched.net"}
        )
        assert resp.status_code == 404

    def test_add_to_another_tenants_brand_is_404(self, client, session):
        other_tenant = Tenant(name=f"custom-other-{uuid.uuid4()}", plan_id="free")
        session.add(other_tenant)
        session.flush()
        other_brand = Brand(
            tenant_id=other_tenant.tenant_id,
            name="not-yours",
            keywords=[],
            tlds=["com"],
            variant_rules=[],
            custom_domains=[],
            active=True,
        )
        session.add(other_brand)
        session.commit()

        try:
            resp = client.post(
                f"/api/brands/{other_brand.brand_id}/custom-domains",
                json={"domain": "watched.net"},
            )
            assert resp.status_code == 404
        finally:
            session.query(Brand).filter_by(brand_id=other_brand.brand_id).delete()
            session.query(Tenant).filter_by(tenant_id=other_tenant.tenant_id).delete()
            session.commit()


class TestOwnedDomains:
    def test_add_and_list(self, client):
        brand = client.post("/api/brands", json={"name": "acme"}).json()

        resp = client.post(
            f"/api/brands/{brand['brand_id']}/owned-domains",
            json={"domain": "Acme-Shop.COM"},
        )

        assert resp.status_code == 201
        assert resp.json()["owned_domains"] == ["acme-shop.com"]  # normalized

    def test_adding_same_domain_twice_does_not_duplicate(self, client):
        brand = client.post("/api/brands", json={"name": "acme"}).json()
        url = f"/api/brands/{brand['brand_id']}/owned-domains"

        client.post(url, json={"domain": "acme-shop.com"})
        resp = client.post(url, json={"domain": "acme-shop.com"})

        assert resp.json()["owned_domains"] == ["acme-shop.com"]

    def test_invalid_domain_is_422(self, client):
        brand = client.post("/api/brands", json={"name": "acme"}).json()

        resp = client.post(
            f"/api/brands/{brand['brand_id']}/owned-domains",
            json={"domain": "this is not a domain"},
        )

        assert resp.status_code == 422

    def test_remove(self, client):
        brand = client.post("/api/brands", json={"name": "acme"}).json()
        url = f"/api/brands/{brand['brand_id']}/owned-domains"
        client.post(url, json={"domain": "acme-shop.com"})

        resp = client.delete(f"{url}/acme-shop.com")

        assert resp.status_code == 200
        assert resp.json()["owned_domains"] == []

    def test_remove_nonexistent_entry_is_a_no_op_not_an_error(self, client):
        brand = client.post("/api/brands", json={"name": "acme"}).json()

        resp = client.delete(f"/api/brands/{brand['brand_id']}/owned-domains/never-added.net")

        assert resp.status_code == 200
        assert resp.json()["owned_domains"] == []

    def test_add_to_nonexistent_brand_is_404(self, client):
        resp = client.post(
            f"/api/brands/{uuid.uuid4()}/owned-domains", json={"domain": "acme-shop.com"}
        )
        assert resp.status_code == 404

    def test_add_to_another_tenants_brand_is_404(self, client, session):
        other_tenant = Tenant(name=f"owned-other-{uuid.uuid4()}", plan_id="free")
        session.add(other_tenant)
        session.flush()
        other_brand = Brand(
            tenant_id=other_tenant.tenant_id,
            name="not-yours",
            keywords=[],
            tlds=["com"],
            variant_rules=[],
            custom_domains=[],
            active=True,
        )
        session.add(other_brand)
        session.commit()

        try:
            resp = client.post(
                f"/api/brands/{other_brand.brand_id}/owned-domains",
                json={"domain": "acme-shop.com"},
            )
            assert resp.status_code == 404
        finally:
            session.query(Brand).filter_by(brand_id=other_brand.brand_id).delete()
            session.query(Tenant).filter_by(tenant_id=other_tenant.tenant_id).delete()
            session.commit()

    def test_adding_as_owned_removes_it_from_custom_domains(self, client):
        """Watching your own domain as a squat candidate is a
        contradiction worth resolving, not leaving in place."""
        brand = client.post("/api/brands", json={"name": "acme"}).json()
        client.post(
            f"/api/brands/{brand['brand_id']}/custom-domains",
            json={"domain": "acme-shop.com"},
        )

        resp = client.post(
            f"/api/brands/{brand['brand_id']}/owned-domains",
            json={"domain": "acme-shop.com"},
        )

        body = resp.json()
        assert body["owned_domains"] == ["acme-shop.com"]
        assert body["custom_domains"] == []


class TestFindingsRoutes:
    def test_list_with_no_brands_returns_empty(self, client):
        resp = client.get("/api/findings")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_unknown_brand_id_is_404(self, client):
        resp = client.get(f"/api/findings?brand_id={uuid.uuid4()}")
        assert resp.status_code == 404

    def test_findings_scoped_to_own_brand(self, client, session):
        brand = client.post("/api/brands", json={"name": "findme"}).json()

        resp = client.get(f"/api/findings?brand_id={brand['brand_id']}")
        assert resp.status_code == 200
        assert resp.json() == []  # no findings written yet, but the brand check passes

    def test_new_finding_defaults_to_open(self, client, session):
        brand = client.post("/api/brands", json={"name": "acme"}).json()
        brand_id = uuid.UUID(brand["brand_id"])
        finding = Finding(
            domain="acme-login.com", brand_id=brand_id, source="generated", status="registered"
        )
        session.add(finding)
        session.commit()

        try:
            body = client.get(f"/api/findings?brand_id={brand_id}").json()
            assert body[0]["resolution_status"] == "open"
            assert body[0]["resolution_note"] is None
        finally:
            session.query(Finding).filter_by(brand_id=brand_id).delete()
            session.commit()

    def test_filters_by_status_and_resolution_status(self, client, session):
        brand = client.post("/api/brands", json={"name": "acme"}).json()
        brand_id = uuid.UUID(brand["brand_id"])
        session.add_all(
            [
                Finding(
                    domain="registered.com",
                    brand_id=brand_id,
                    source="generated",
                    status="registered",
                    resolution_status="open",
                ),
                Finding(
                    domain="unregistered.com",
                    brand_id=brand_id,
                    source="manual",
                    status="unregistered",
                    resolution_status="open",
                ),
                Finding(
                    domain="closed.com",
                    brand_id=brand_id,
                    source="generated",
                    status="registered",
                    resolution_status="resolved",
                ),
            ]
        )
        session.commit()

        try:
            registered_only = client.get(
                f"/api/findings?brand_id={brand_id}&status=registered"
            ).json()
            assert {f["domain"] for f in registered_only} == {"registered.com", "closed.com"}

            open_only = client.get(
                f"/api/findings?brand_id={brand_id}&status=registered&resolution_status=open"
            ).json()
            assert {f["domain"] for f in open_only} == {"registered.com"}
        finally:
            session.query(Finding).filter_by(brand_id=brand_id).delete()
            session.commit()


class TestFindingResolution:
    def test_mark_resolved(self, client, session):
        brand = client.post("/api/brands", json={"name": "acme"}).json()
        brand_id = uuid.UUID(brand["brand_id"])
        session.add(
            Finding(
                domain="acme-login.com", brand_id=brand_id, source="generated", status="registered"
            )
        )
        session.commit()

        try:
            resp = client.post(
                f"/api/findings/acme-login.com/resolution?brand_id={brand_id}",
                json={"status": "resolved", "note": "took it down"},
            )

            assert resp.status_code == 200
            body = resp.json()
            assert body["resolution_status"] == "resolved"
            assert body["resolution_note"] == "took it down"
        finally:
            session.query(FindingEvent).filter_by(brand_id=brand_id).delete()
            session.query(Finding).filter_by(brand_id=brand_id).delete()
            session.commit()

    def test_record_resolution_failed(self, client, session):
        brand = client.post("/api/brands", json={"name": "acme"}).json()
        brand_id = uuid.UUID(brand["brand_id"])
        session.add(
            Finding(
                domain="acme-login.com", brand_id=brand_id, source="generated", status="registered"
            )
        )
        session.commit()

        try:
            resp = client.post(
                f"/api/findings/acme-login.com/resolution?brand_id={brand_id}",
                json={"status": "resolution_failed", "note": "registrar unresponsive"},
            )

            assert resp.json()["resolution_status"] == "resolution_failed"
        finally:
            session.query(FindingEvent).filter_by(brand_id=brand_id).delete()
            session.query(Finding).filter_by(brand_id=brand_id).delete()
            session.commit()

    def test_claim_as_owned_adds_to_owned_domains_and_resolves(self, client, session):
        brand = client.post("/api/brands", json={"name": "acme"}).json()
        brand_id = uuid.UUID(brand["brand_id"])
        session.add(
            Finding(
                domain="acme-shop.com", brand_id=brand_id, source="generated", status="registered"
            )
        )
        session.commit()

        try:
            resp = client.post(
                f"/api/findings/acme-shop.com/resolution?brand_id={brand_id}",
                json={"status": "resolved_owned"},
            )

            assert resp.status_code == 200
            assert resp.json()["resolution_status"] == "resolved_owned"

            brand_after = client.get("/api/brands").json()[0]
            assert brand_after["owned_domains"] == ["acme-shop.com"]
        finally:
            session.query(FindingEvent).filter_by(brand_id=brand_id).delete()
            session.query(Finding).filter_by(brand_id=brand_id).delete()
            session.commit()

    def test_invalid_status_is_422(self, client):
        brand = client.post("/api/brands", json={"name": "acme"}).json()

        resp = client.post(
            f"/api/findings/whatever.com/resolution?brand_id={brand['brand_id']}",
            json={"status": "not-a-real-status"},
        )

        assert resp.status_code == 422

    def test_unknown_finding_is_404(self, client):
        brand = client.post("/api/brands", json={"name": "acme"}).json()

        resp = client.post(
            f"/api/findings/never-existed.com/resolution?brand_id={brand['brand_id']}",
            json={"status": "resolved"},
        )

        assert resp.status_code == 404

    def test_another_tenants_brand_is_404(self, client, session):
        other_tenant = Tenant(name=f"resolution-other-{uuid.uuid4()}", plan_id="free")
        session.add(other_tenant)
        session.flush()
        other_brand = Brand(
            tenant_id=other_tenant.tenant_id,
            name="not-yours",
            keywords=[],
            tlds=["com"],
            variant_rules=[],
            custom_domains=[],
            active=True,
        )
        session.add(other_brand)
        session.commit()

        try:
            resp = client.post(
                f"/api/findings/whatever.com/resolution?brand_id={other_brand.brand_id}",
                json={"status": "resolved"},
            )
            assert resp.status_code == 404
        finally:
            session.query(Brand).filter_by(brand_id=other_brand.brand_id).delete()
            session.query(Tenant).filter_by(tenant_id=other_tenant.tenant_id).delete()
            session.commit()


class TestFindingsCsvExport:
    def test_export_unknown_brand_is_404(self, client):
        resp = client.get(f"/api/findings/export.csv?brand_id={uuid.uuid4()}")
        assert resp.status_code == 404

    def test_export_empty_still_has_header_row(self, client):
        resp = client.get("/api/findings/export.csv")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/csv")
        assert "attachment; filename=findings.csv" in resp.headers["content-disposition"]

        rows = list(csv.reader(io.StringIO(resp.text)))
        assert rows == [
            [
                "domain",
                "brand_id",
                "source",
                "status",
                "registrar",
                "created_date",
                "abuse_email",
                "risk_score",
                "risk_factors",
                "first_seen",
                "last_checked",
            ]
        ]

    def test_export_includes_real_finding_data(self, client, session):
        brand = client.post("/api/brands", json={"name": "csvbrand"}).json()
        finding = Finding(
            domain="csvbrand-login.com",
            brand_id=uuid.UUID(brand["brand_id"]),
            source="generated",
            status="registered",
            registrar="Example Registrar",
            risk_score=75,
            risk_factors=["edit_distance<=1", "mx_configured"],
        )
        session.add(finding)
        session.commit()

        try:
            resp = client.get("/api/findings/export.csv")
            rows = list(csv.reader(io.StringIO(resp.text)))

            assert len(rows) == 2  # header + one finding
            data_row = dict(zip(rows[0], rows[1], strict=True))
            assert data_row["domain"] == "csvbrand-login.com"
            assert data_row["registrar"] == "Example Registrar"
            assert data_row["risk_score"] == "75"
            assert data_row["risk_factors"] == "edit_distance<=1;mx_configured"
        finally:
            session.query(Finding).filter_by(domain="csvbrand-login.com").delete()
            session.commit()

    def test_export_scoped_to_own_tenant(self, client, session):
        """A tenant must never see another tenant's findings in the CSV,
        same as the JSON endpoint — no separate access-control bug to
        introduce for the export path."""
        other_tenant = Tenant(name=f"csv-other-{uuid.uuid4()}", plan_id="free")
        session.add(other_tenant)
        session.flush()
        other_brand = Brand(
            tenant_id=other_tenant.tenant_id,
            name="not-yours",
            keywords=[],
            tlds=["com"],
            variant_rules=[],
            active=True,
        )
        session.add(other_brand)
        session.flush()
        other_finding = Finding(
            domain="secret-finding.com",
            brand_id=other_brand.brand_id,
            source="generated",
            status="registered",
        )
        session.add(other_finding)
        session.commit()

        try:
            resp = client.get("/api/findings/export.csv")
            assert "secret-finding.com" not in resp.text
        finally:
            session.query(Finding).filter_by(domain="secret-finding.com").delete()
            session.query(Brand).filter_by(brand_id=other_brand.brand_id).delete()
            session.query(Tenant).filter_by(tenant_id=other_tenant.tenant_id).delete()
            session.commit()


def test_cross_tenant_brand_access_is_404_not_leaked(client, session):
    """A brand belonging to a *different* tenant must 404, not 403 —
    confirms the 404 branch actually distinguishes ownership, not just
    existence."""
    other_tenant = Tenant(name=f"other-{uuid.uuid4()}", plan_id="free")
    session.add(other_tenant)
    session.flush()
    other_brand = Brand(
        tenant_id=other_tenant.tenant_id,
        name="not-yours",
        keywords=[],
        tlds=["com"],
        variant_rules=[],
        active=True,
    )
    session.add(other_brand)
    session.commit()

    try:
        resp = client.delete(f"/api/brands/{other_brand.brand_id}")
        assert resp.status_code == 404

        resp = client.get(f"/api/findings?brand_id={other_brand.brand_id}")
        assert resp.status_code == 404
    finally:
        session.query(Brand).filter_by(brand_id=other_brand.brand_id).delete()
        session.query(Tenant).filter_by(tenant_id=other_tenant.tenant_id).delete()
        session.commit()


class TestFindingIncidents:
    def test_empty_when_no_incidents_recorded(self, client):
        brand = client.post("/api/brands", json={"name": "acme"}).json()

        resp = client.get(f"/api/findings/somedomain.com/incidents?brand_id={brand['brand_id']}")

        assert resp.status_code == 200
        assert resp.json() == []

    def test_missing_brand_id_is_422(self, client):
        resp = client.get("/api/findings/somedomain.com/incidents")
        assert resp.status_code == 422  # brand_id is a required query param

    def test_returns_recorded_incidents_newest_first(self, client, session):
        brand = client.post("/api/brands", json={"name": "acme"}).json()
        brand_id = uuid.UUID(brand["brand_id"])
        finding = Finding(
            domain="acme-login.com", brand_id=brand_id, source="generated", status="registered"
        )
        session.add(finding)
        session.flush()
        older = FindingEvent(
            id=uuid.uuid4(),
            brand_id=brand_id,
            domain="acme-login.com",
            event_type="registered",
            details={"registrar": "GoDaddy"},
        )
        session.add(older)
        session.commit()
        newer = FindingEvent(
            id=uuid.uuid4(),
            brand_id=brand_id,
            domain="acme-login.com",
            event_type="form_detected",
            details={"form_count": 1},
        )
        session.add(newer)
        session.commit()

        try:
            resp = client.get(f"/api/findings/acme-login.com/incidents?brand_id={brand_id}")
            body = resp.json()

            assert resp.status_code == 200
            assert len(body) == 2
            assert body[0]["event_type"] == "form_detected"  # newest first
            assert body[1]["event_type"] == "registered"
            assert body[1]["details"] == {"registrar": "GoDaddy"}
        finally:
            session.query(FindingEvent).filter_by(brand_id=brand_id).delete()
            session.query(Finding).filter_by(brand_id=brand_id).delete()
            session.commit()

    def test_another_tenants_brand_is_404(self, client, session):
        other_tenant = Tenant(name=f"incidents-other-{uuid.uuid4()}", plan_id="free")
        session.add(other_tenant)
        session.flush()
        other_brand = Brand(
            tenant_id=other_tenant.tenant_id,
            name="not-yours",
            keywords=[],
            tlds=["com"],
            variant_rules=[],
            active=True,
        )
        session.add(other_brand)
        session.commit()

        try:
            resp = client.get(
                f"/api/findings/whatever.com/incidents?brand_id={other_brand.brand_id}"
            )
            assert resp.status_code == 404
        finally:
            session.query(Brand).filter_by(brand_id=other_brand.brand_id).delete()
            session.query(Tenant).filter_by(tenant_id=other_tenant.tenant_id).delete()
            session.commit()


class TestFindingReportPdf:
    def test_returns_a_real_pdf(self, client, session):
        brand = client.post("/api/brands", json={"name": "acme"}).json()
        brand_id = uuid.UUID(brand["brand_id"])
        finding = Finding(
            domain="acme-login.com",
            brand_id=brand_id,
            source="generated",
            status="registered",
            registrar="Example Registrar",
            abuse_email="abuse@example-registrar.test",
            risk_score=75,
            risk_factors=["edit_distance<=1"],
        )
        session.add(finding)
        session.commit()

        try:
            resp = client.get(f"/api/findings/acme-login.com/report.pdf?brand_id={brand_id}")

            assert resp.status_code == 200
            assert resp.headers["content-type"] == "application/pdf"
            assert "acme-login.com-report.pdf" in resp.headers["content-disposition"]
            assert resp.content[:4] == b"%PDF"
        finally:
            session.query(Finding).filter_by(brand_id=brand_id).delete()
            session.commit()

    def test_unknown_finding_is_404(self, client):
        brand = client.post("/api/brands", json={"name": "acme"}).json()

        resp = client.get(
            f"/api/findings/never-existed.com/report.pdf?brand_id={brand['brand_id']}"
        )

        assert resp.status_code == 404

    def test_missing_brand_id_is_422(self, client):
        resp = client.get("/api/findings/somedomain.com/report.pdf")
        assert resp.status_code == 422

    def test_another_tenants_brand_is_404(self, client, session):
        other_tenant = Tenant(name=f"report-other-{uuid.uuid4()}", plan_id="free")
        session.add(other_tenant)
        session.flush()
        other_brand = Brand(
            tenant_id=other_tenant.tenant_id,
            name="not-yours",
            keywords=[],
            tlds=["com"],
            variant_rules=[],
            active=True,
        )
        session.add(other_brand)
        session.commit()

        try:
            resp = client.get(
                f"/api/findings/whatever.com/report.pdf?brand_id={other_brand.brand_id}"
            )
            assert resp.status_code == 404
        finally:
            session.query(Brand).filter_by(brand_id=other_brand.brand_id).delete()
            session.query(Tenant).filter_by(tenant_id=other_tenant.tenant_id).delete()
            session.commit()


class TestFindingSiteGraph:
    def test_empty_when_no_pages_crawled(self, client):
        brand = client.post("/api/brands", json={"name": "acme"}).json()

        resp = client.get(f"/api/findings/somedomain.com/site-graph?brand_id={brand['brand_id']}")

        assert resp.status_code == 200
        assert resp.json() == {"pages": [], "links": []}

    def test_missing_brand_id_is_422(self, client):
        resp = client.get("/api/findings/somedomain.com/site-graph")
        assert resp.status_code == 422

    def test_returns_recorded_pages_and_links(self, client, session):
        brand = client.post("/api/brands", json={"name": "acme"}).json()
        brand_id = uuid.UUID(brand["brand_id"])
        finding = Finding(
            domain="acme-login.com", brand_id=brand_id, source="generated", status="registered"
        )
        session.add(finding)
        session.flush()
        page = CrawledPage(
            brand_id=brand_id,
            domain="acme-login.com",
            url="https://acme-login.com/",
            status_code=200,
            content_hash="h1",
            last_modified="Mon, 01 Jan 2026 00:00:00 GMT",
            etag='"abc"',
            title="Home",
            has_forms=True,
            form_count=1,
            has_password_field=True,
        )
        link = PageLink(
            brand_id=brand_id,
            domain="acme-login.com",
            from_url="https://acme-login.com/",
            to_url="https://acme-login.com/about",
            is_external=False,
        )
        session.add_all([page, link])
        session.commit()

        try:
            resp = client.get(f"/api/findings/acme-login.com/site-graph?brand_id={brand_id}")
            body = resp.json()

            assert resp.status_code == 200
            assert len(body["pages"]) == 1
            assert body["pages"][0]["url"] == "https://acme-login.com/"
            assert body["pages"][0]["content_hash"] == "h1"
            assert body["pages"][0]["has_password_field"] is True
            assert len(body["links"]) == 1
            assert body["links"][0]["to_url"] == "https://acme-login.com/about"
        finally:
            session.query(PageLink).filter_by(brand_id=brand_id).delete()
            session.query(CrawledPage).filter_by(brand_id=brand_id).delete()
            session.query(Finding).filter_by(brand_id=brand_id).delete()
            session.commit()

    def test_another_tenants_brand_is_404(self, client, session):
        other_tenant = Tenant(name=f"site-graph-other-{uuid.uuid4()}", plan_id="free")
        session.add(other_tenant)
        session.flush()
        other_brand = Brand(
            tenant_id=other_tenant.tenant_id,
            name="not-yours",
            keywords=[],
            tlds=["com"],
            variant_rules=[],
            active=True,
        )
        session.add(other_brand)
        session.commit()

        try:
            resp = client.get(
                f"/api/findings/whatever.com/site-graph?brand_id={other_brand.brand_id}"
            )
            assert resp.status_code == 404
        finally:
            session.query(Brand).filter_by(brand_id=other_brand.brand_id).delete()
            session.query(Tenant).filter_by(tenant_id=other_tenant.tenant_id).delete()
            session.commit()
