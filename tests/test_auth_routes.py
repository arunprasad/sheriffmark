"""HTTP-level tests for local register/login/verify and the /providers
capability endpoint. SAML routes are covered separately in
tests/test_saml_auth.py (unit-level, since exercising a real IdP
round-trip needs a live IdP)."""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from shared.config import settings
from shared.db import SessionLocal, get_session
from shared.models import LocalCredential
from web.api.main import app


@pytest.fixture
def session():
    s = SessionLocal()
    yield s
    s.rollback()
    s.query(LocalCredential).delete()
    s.commit()
    s.close()


@pytest.fixture
def client(session):
    def override_get_session():
        yield session

    app.dependency_overrides[get_session] = override_get_session
    yield TestClient(app)
    app.dependency_overrides.clear()


class TestProviders:
    def test_reports_configured_providers(self, client):
        with patch.object(settings, "auth_enable_local", True), patch.object(
            settings, "auth_enable_oidc", False
        ), patch.object(settings, "auth_enable_saml", False), patch.object(
            settings, "smtp_host", ""
        ):
            resp = client.get("/api/auth/providers")

        assert resp.status_code == 200
        body = resp.json()
        assert body == {
            "local": True,
            "oidc": False,
            "saml": False,
            "local_requires_verification": False,
        }


class TestRegisterAndLogin:
    def test_register_without_smtp_returns_a_usable_token(self, client):
        with patch.object(settings, "auth_enable_local", True), patch.object(
            settings, "smtp_host", ""
        ):
            resp = client.post(
                "/api/auth/register", json={"email": "a@example.com", "password": "password123"}
            )

        assert resp.status_code == 201
        body = resp.json()
        assert body["access_token"]
        assert body["email_verification_required"] is False

    def test_register_with_smtp_sends_verification_and_withholds_token(self, client):
        with patch.object(settings, "auth_enable_local", True), patch.object(
            settings, "smtp_host", "smtp.example.com"
        ), patch("web.api.routes.auth.send_raw_email") as mock_send:
            resp = client.post(
                "/api/auth/register", json={"email": "a@example.com", "password": "password123"}
            )

        assert resp.status_code == 201
        body = resp.json()
        assert body["access_token"] == ""
        assert body["email_verification_required"] is True
        mock_send.assert_called_once()

    def test_duplicate_registration_is_409(self, client):
        with patch.object(settings, "auth_enable_local", True), patch.object(
            settings, "smtp_host", ""
        ):
            client.post(
                "/api/auth/register", json={"email": "a@example.com", "password": "password123"}
            )
            resp = client.post(
                "/api/auth/register", json={"email": "a@example.com", "password": "password123"}
            )

        assert resp.status_code == 409

    def test_short_password_is_422(self, client):
        with patch.object(settings, "auth_enable_local", True):
            resp = client.post(
                "/api/auth/register", json={"email": "a@example.com", "password": "short"}
            )

        assert resp.status_code == 422

    def test_login_with_correct_credentials_succeeds(self, client):
        with patch.object(settings, "auth_enable_local", True), patch.object(
            settings, "smtp_host", ""
        ):
            client.post(
                "/api/auth/register", json={"email": "a@example.com", "password": "password123"}
            )
            resp = client.post(
                "/api/auth/login", json={"email": "a@example.com", "password": "password123"}
            )

        assert resp.status_code == 200
        assert resp.json()["access_token"]

    def test_login_with_wrong_password_is_401(self, client):
        with patch.object(settings, "auth_enable_local", True), patch.object(
            settings, "smtp_host", ""
        ):
            client.post(
                "/api/auth/register", json={"email": "a@example.com", "password": "password123"}
            )
            resp = client.post(
                "/api/auth/login", json={"email": "a@example.com", "password": "wrong-password"}
            )

        assert resp.status_code == 401

    def test_login_before_verification_is_403(self, client):
        with patch.object(settings, "auth_enable_local", True), patch.object(
            settings, "smtp_host", "smtp.example.com"
        ), patch("web.api.routes.auth.send_raw_email"):
            client.post(
                "/api/auth/register", json={"email": "a@example.com", "password": "password123"}
            )
            resp = client.post(
                "/api/auth/login", json={"email": "a@example.com", "password": "password123"}
            )

        assert resp.status_code == 403

    def test_disabled_provider_is_404(self, client):
        with patch.object(settings, "auth_enable_local", False):
            resp = client.post(
                "/api/auth/login", json={"email": "a@example.com", "password": "password123"}
            )

        assert resp.status_code == 404


class TestVerify:
    def test_valid_token_verifies_and_allows_login(self, client):
        with patch.object(settings, "auth_enable_local", True), patch.object(
            settings, "smtp_host", "smtp.example.com"
        ), patch("web.api.routes.auth.send_raw_email") as mock_send:
            client.post(
                "/api/auth/register", json={"email": "a@example.com", "password": "password123"}
            )
            verify_url = mock_send.call_args[0][3].split("\n\n")[1].split("\n")[0]
            token = verify_url.split("token=")[1]

            verify_resp = client.get(f"/api/auth/verify?token={token}")
            login_resp = client.post(
                "/api/auth/login", json={"email": "a@example.com", "password": "password123"}
            )

        assert verify_resp.status_code == 200
        assert login_resp.status_code == 200

    def test_bogus_token_is_400(self, client):
        with patch.object(settings, "auth_enable_local", True):
            resp = client.get("/api/auth/verify?token=not-real")

        assert resp.status_code == 400
