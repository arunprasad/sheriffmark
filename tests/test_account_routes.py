"""API-level tests for account settings (Tenant.contact_email/
notification_channels) — same fixture pattern as test_api_routes.py."""

import uuid

import pytest
from fastapi.testclient import TestClient

from shared.db import SessionLocal, get_session
from shared.models import Brand, Tenant, User
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
    external_id = f"test-account-{uuid.uuid4()}"
    fake_user = AuthenticatedUser(external_id=external_id, email="account-test@example.com")

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
            session.query(Tenant.tenant_id).filter_by(name="account-test@example.com")
        )
    ).delete(synchronize_session=False)
    session.query(User).filter_by(external_id=external_id).delete()
    session.query(Tenant).filter_by(name="account-test@example.com").delete()
    session.commit()


class TestGetAccount:
    def test_returns_the_tenant(self, client):
        resp = client.get("/api/account")

        assert resp.status_code == 200
        body = resp.json()
        assert body["name"] == "account-test@example.com"
        assert body["contact_email"] is None
        assert body["notification_channels"] == {}


class TestUpdateAccount:
    def test_sets_contact_email(self, client):
        resp = client.patch("/api/account", json={"contact_email": "ops@acme.com"})

        assert resp.status_code == 200
        assert resp.json()["contact_email"] == "ops@acme.com"

    def test_sets_a_notification_channel(self, client):
        resp = client.patch(
            "/api/account",
            json={"notification_channels": {"slack_webhook_url": "https://hooks.slack/x"}},
        )

        assert resp.json()["notification_channels"] == {
            "slack_webhook_url": "https://hooks.slack/x"
        }

    def test_updating_one_channel_does_not_wipe_another(self, client):
        client.patch(
            "/api/account",
            json={"notification_channels": {"slack_webhook_url": "https://hooks.slack/x"}},
        )

        resp = client.patch(
            "/api/account",
            json={"notification_channels": {"discord_webhook_url": "https://discord/y"}},
        )

        body = resp.json()["notification_channels"]
        assert body["slack_webhook_url"] == "https://hooks.slack/x"
        assert body["discord_webhook_url"] == "https://discord/y"

    def test_empty_string_clears_a_channel(self, client):
        client.patch(
            "/api/account",
            json={"notification_channels": {"slack_webhook_url": "https://hooks.slack/x"}},
        )

        resp = client.patch(
            "/api/account", json={"notification_channels": {"slack_webhook_url": ""}}
        )

        assert resp.json()["notification_channels"]["slack_webhook_url"] == ""

    def test_empty_body_is_a_no_op(self, client):
        client.patch("/api/account", json={"contact_email": "ops@acme.com"})

        resp = client.patch("/api/account", json={})

        assert resp.json()["contact_email"] == "ops@acme.com"
