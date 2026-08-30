"""API-level tests for reference image upload/list/get/delete and the
finding screenshot endpoint — same fixture pattern as
tests/test_api_routes.py (a real disposable tenant per test)."""

import io
import uuid

import pytest
from fastapi.testclient import TestClient

from shared.db import SessionLocal, get_session
from shared.models import Brand, Finding, ReferenceImage, Tenant, User
from web.api.auth import AuthenticatedUser
from web.api.main import app
from web.api.tenancy import get_current_tenant, get_or_create_tenant

_PNG_BYTES = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00"
    b"\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\xcf\xc0\x00\x00\x03\x01\x01\x00\x18\xdd\x8d\xb0"
    b"\x00\x00\x00\x00IEND\xaeB`\x82"
)  # a real, valid 1x1 PNG


@pytest.fixture
def session():
    s = SessionLocal()
    yield s
    s.rollback()
    s.close()


@pytest.fixture
def client(session):
    external_id = f"test-refimg-{uuid.uuid4()}"
    fake_user = AuthenticatedUser(external_id=external_id, email="refimg-test@example.com")

    def override_get_session():
        yield session

    def override_get_current_tenant():
        return get_or_create_tenant(session, fake_user)

    app.dependency_overrides[get_session] = override_get_session
    app.dependency_overrides[get_current_tenant] = override_get_current_tenant

    yield TestClient(app)

    app.dependency_overrides.clear()
    brand_ids = session.query(Brand.brand_id).filter(
        Brand.tenant_id.in_(
            session.query(Tenant.tenant_id).filter_by(name="refimg-test@example.com")
        )
    )
    session.query(ReferenceImage).filter(ReferenceImage.brand_id.in_(brand_ids)).delete(
        synchronize_session=False
    )
    session.query(Finding).filter(Finding.brand_id.in_(brand_ids)).delete(
        synchronize_session=False
    )
    session.query(Brand).filter(Brand.brand_id.in_(brand_ids)).delete(synchronize_session=False)
    session.query(User).filter_by(external_id=external_id).delete()
    session.query(Tenant).filter_by(name="refimg-test@example.com").delete()
    session.commit()


class TestUploadReferenceImage:
    def test_uploads_a_logo(self, client):
        brand = client.post("/api/brands", json={"name": "acme"}).json()

        resp = client.post(
            f"/api/brands/{brand['brand_id']}/reference-images",
            data={"kind": "logo"},
            files={"file": ("logo.png", io.BytesIO(_PNG_BYTES), "image/png")},
        )

        assert resp.status_code == 201
        body = resp.json()
        assert body["kind"] == "logo"
        assert body["filename"] == "logo.png"
        assert body["content_type"] == "image/png"

    def test_invalid_kind_is_422(self, client):
        brand = client.post("/api/brands", json={"name": "acme"}).json()

        resp = client.post(
            f"/api/brands/{brand['brand_id']}/reference-images",
            data={"kind": "not-a-real-kind"},
            files={"file": ("logo.png", io.BytesIO(_PNG_BYTES), "image/png")},
        )

        assert resp.status_code == 422

    def test_disallowed_content_type_is_422(self, client):
        brand = client.post("/api/brands", json={"name": "acme"}).json()

        resp = client.post(
            f"/api/brands/{brand['brand_id']}/reference-images",
            data={"kind": "logo"},
            files={"file": ("logo.svg", io.BytesIO(b"<svg></svg>"), "image/svg+xml")},
        )

        assert resp.status_code == 422

    def test_oversized_upload_is_413(self, client):
        brand = client.post("/api/brands", json={"name": "acme"}).json()
        oversized = b"\x00" * (2_000_001)

        resp = client.post(
            f"/api/brands/{brand['brand_id']}/reference-images",
            data={"kind": "logo"},
            files={"file": ("logo.png", io.BytesIO(oversized), "image/png")},
        )

        assert resp.status_code == 413

    def test_empty_upload_is_422(self, client):
        brand = client.post("/api/brands", json={"name": "acme"}).json()

        resp = client.post(
            f"/api/brands/{brand['brand_id']}/reference-images",
            data={"kind": "logo"},
            files={"file": ("logo.png", io.BytesIO(b""), "image/png")},
        )

        assert resp.status_code == 422

    def test_another_tenants_brand_is_404(self, client, session):
        other_tenant = Tenant(name=f"refimg-other-{uuid.uuid4()}", plan_id="free")
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
            resp = client.post(
                f"/api/brands/{other_brand.brand_id}/reference-images",
                data={"kind": "logo"},
                files={"file": ("logo.png", io.BytesIO(_PNG_BYTES), "image/png")},
            )
            assert resp.status_code == 404
        finally:
            session.query(Brand).filter_by(brand_id=other_brand.brand_id).delete()
            session.query(Tenant).filter_by(tenant_id=other_tenant.tenant_id).delete()
            session.commit()


class TestListGetDeleteReferenceImage:
    def test_list_and_get_and_delete_round_trip(self, client):
        brand = client.post("/api/brands", json={"name": "acme"}).json()
        upload = client.post(
            f"/api/brands/{brand['brand_id']}/reference-images",
            data={"kind": "site_screenshot"},
            files={"file": ("home.png", io.BytesIO(_PNG_BYTES), "image/png")},
        ).json()

        list_resp = client.get(f"/api/brands/{brand['brand_id']}/reference-images")
        assert list_resp.status_code == 200
        assert len(list_resp.json()) == 1

        get_resp = client.get(
            f"/api/brands/{brand['brand_id']}/reference-images/{upload['id']}"
        )
        assert get_resp.status_code == 200
        assert get_resp.content == _PNG_BYTES
        assert get_resp.headers["content-type"] == "image/png"

        delete_resp = client.delete(
            f"/api/brands/{brand['brand_id']}/reference-images/{upload['id']}"
        )
        assert delete_resp.status_code == 204

        list_after = client.get(f"/api/brands/{brand['brand_id']}/reference-images")
        assert list_after.json() == []

    def test_get_unknown_image_is_404(self, client):
        brand = client.post("/api/brands", json={"name": "acme"}).json()

        resp = client.get(f"/api/brands/{brand['brand_id']}/reference-images/{uuid.uuid4()}")

        assert resp.status_code == 404

    def test_delete_unknown_image_is_404(self, client):
        brand = client.post("/api/brands", json={"name": "acme"}).json()

        resp = client.delete(
            f"/api/brands/{brand['brand_id']}/reference-images/{uuid.uuid4()}"
        )

        assert resp.status_code == 404


class TestFindingScreenshot:
    def test_no_screenshot_captured_is_404(self, client):
        brand = client.post("/api/brands", json={"name": "acme"}).json()

        resp = client.get(
            f"/api/findings/somedomain.com/screenshot?brand_id={brand['brand_id']}"
        )

        assert resp.status_code == 404

    def test_returns_the_stored_screenshot(self, client, session):
        brand = client.post("/api/brands", json={"name": "acme"}).json()
        brand_id = uuid.UUID(brand["brand_id"])
        finding = Finding(
            domain="acme-login.com",
            brand_id=brand_id,
            source="generated",
            status="registered",
            screenshot_data=_PNG_BYTES,
            screenshot_content_type="image/png",
        )
        session.add(finding)
        session.commit()

        try:
            resp = client.get(
                f"/api/findings/acme-login.com/screenshot?brand_id={brand_id}"
            )

            assert resp.status_code == 200
            assert resp.content == _PNG_BYTES
            assert resp.headers["content-type"] == "image/png"
        finally:
            session.query(Finding).filter_by(brand_id=brand_id).delete()
            session.commit()

    def test_another_tenants_brand_is_404(self, client, session):
        other_tenant = Tenant(name=f"screenshot-other-{uuid.uuid4()}", plan_id="free")
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
                f"/api/findings/whatever.com/screenshot?brand_id={other_brand.brand_id}"
            )
            assert resp.status_code == 404
        finally:
            session.query(Brand).filter_by(brand_id=other_brand.brand_id).delete()
            session.query(Tenant).filter_by(tenant_id=other_tenant.tenant_id).delete()
            session.commit()
