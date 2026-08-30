from unittest.mock import MagicMock, patch

import jwt
import pytest

from shared.config import settings
from web.api.auth import get_current_user, verify_token


class TestVerifyTokenRouting:
    """verify_token routes by the token's (unverified) `iss` claim —
    settings.auth_local_issuer means "verify against our own signing
    keys table"; anything else means "verify against the external OIDC
    JWKS". See web/api/auth.py."""

    @patch("web.api.auth._verify_local")
    def test_local_issuer_routes_to_local_verification(self, mock_verify_local):
        claims = {"iss": settings.auth_local_issuer, "sub": "local:1"}
        token = jwt.encode(claims, "x", algorithm="HS256")
        mock_verify_local.return_value = "the-result"
        session = MagicMock()

        result = verify_token(token, session)

        mock_verify_local.assert_called_once_with(token, session)
        assert result == "the-result"

    @patch("web.api.auth._verify_oidc")
    def test_other_issuer_routes_to_oidc_verification(self, mock_verify_oidc):
        claims = {"iss": "https://my-idp.example.com", "sub": "u1"}
        token = jwt.encode(claims, "x", algorithm="HS256")
        mock_verify_oidc.return_value = "the-result"

        result = verify_token(token, MagicMock())

        mock_verify_oidc.assert_called_once_with(token)
        assert result == "the-result"

    @patch("web.api.auth._verify_oidc")
    def test_missing_issuer_routes_to_oidc_verification(self, mock_verify_oidc):
        token = jwt.encode({"sub": "u1"}, "x", algorithm="HS256")
        mock_verify_oidc.return_value = "the-result"

        verify_token(token, MagicMock())

        mock_verify_oidc.assert_called_once_with(token)


class TestVerifyLocal:
    def test_disabled_provider_raises(self):
        from web.api.auth import _verify_local

        token = jwt.encode(
            {"iss": settings.auth_local_issuer, "sub": "local:1"}, "x", algorithm="HS256"
        )
        with patch.object(settings, "auth_enable_local", False):
            with pytest.raises(jwt.InvalidTokenError):
                _verify_local(token, MagicMock())

    def test_unknown_kid_raises(self):
        from web.api.auth import _verify_local

        token = jwt.encode(
            {"iss": settings.auth_local_issuer, "sub": "local:1"},
            "x",
            algorithm="HS256",
            headers={"kid": "nonexistent"},
        )
        session = MagicMock()
        session.get.return_value = None

        with pytest.raises(jwt.InvalidTokenError):
            _verify_local(token, session)

    def test_valid_local_token_round_trips(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        from web.api.auth import _verify_local

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        public_pem = (
            private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )
        claims = {
            "iss": settings.auth_local_issuer,
            "sub": "local:abc",
            "email": "a@example.com",
            "aud": "authenticated",
        }
        token = jwt.encode(claims, private_pem, algorithm="RS256", headers={"kid": "kid-1"})
        session = MagicMock()
        signing_key = MagicMock(public_key_pem=public_pem)
        session.get.return_value = signing_key

        result = _verify_local(token, session)

        assert result.external_id == "local:abc"
        assert result.email == "a@example.com"


class TestVerifyOidc:
    def test_disabled_provider_raises(self):
        from web.api.auth import _verify_oidc

        with patch.object(settings, "auth_enable_oidc", False):
            with pytest.raises(jwt.InvalidTokenError):
                _verify_oidc("token")

    @patch("web.api.auth._get_oidc_jwk_client")
    def test_valid_token_returns_authenticated_user(self, mock_get_client):
        from web.api.auth import _verify_oidc

        mock_client = MagicMock()
        mock_client.get_signing_key_from_jwt.return_value = MagicMock(key="fake-key")
        mock_get_client.return_value = mock_client

        with patch.object(settings, "auth_enable_oidc", True), patch(
            "web.api.auth.jwt.decode", return_value={"sub": "user-123", "email": "a@example.com"}
        ):
            result = _verify_oidc("fake.jwt.token")

        assert result.external_id == "user-123"
        assert result.email == "a@example.com"

    @patch("web.api.auth._get_oidc_jwk_client")
    def test_invalid_signature_raises(self, mock_get_client):
        from web.api.auth import _verify_oidc

        mock_client = MagicMock()
        mock_client.get_signing_key_from_jwt.side_effect = jwt.InvalidTokenError("bad token")
        mock_get_client.return_value = mock_client

        with patch.object(settings, "auth_enable_oidc", True):
            with pytest.raises(jwt.PyJWTError):
                _verify_oidc("garbage")


class TestGetCurrentUser:
    def test_missing_header_is_401(self):
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            get_current_user(authorization="", session=MagicMock())
        assert exc_info.value.status_code == 401

    def test_non_bearer_header_is_401(self):
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            get_current_user(authorization="Basic dXNlcjpwYXNz", session=MagicMock())
        assert exc_info.value.status_code == 401

    @patch("web.api.auth.verify_token")
    def test_invalid_token_is_401_not_500(self, mock_verify):
        from fastapi import HTTPException

        mock_verify.side_effect = jwt.ExpiredSignatureError("expired")

        with pytest.raises(HTTPException) as exc_info:
            get_current_user(authorization="Bearer expired.token.here", session=MagicMock())
        assert exc_info.value.status_code == 401

    @patch("web.api.auth.verify_token")
    def test_valid_token_returns_user(self, mock_verify):
        from web.api.auth import AuthenticatedUser

        mock_verify.return_value = AuthenticatedUser(external_id="u1", email="x@example.com")

        result = get_current_user(authorization="Bearer good.token.here", session=MagicMock())

        assert result.external_id == "u1"
