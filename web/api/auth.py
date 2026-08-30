"""Token verification for every enabled auth provider.

Every provider — local email/password, external OIDC, SAML — ends up
producing a JWT the frontend sends as a Bearer token (SAML's browser
redirect flow issues one of our own local-provider tokens at the end of
its ACS step; see web/api/saml_auth.py). This module's only job is to
verify that token and extract who it belongs to, routing by the
unverified `iss` claim to whichever provider issued it:

- `iss == settings.auth_local_issuer` -> local provider, verified against
  a signing key from the `signing_keys` table (web/api/crypto_keys.py).
- anything else -> the external OIDC provider (Supabase Auth, Keycloak,
  Auth0, ...), verified against its JWKS endpoint. `PyJWKClient` handles
  fetching + caching the JWKS.

A request for a provider that isn't enabled in config is rejected before
any verification happens.
"""

from dataclasses import dataclass

import jwt
from fastapi import Depends, Header, HTTPException
from jwt import PyJWKClient
from sqlalchemy.orm import Session

from shared.config import settings
from shared.db import get_session
from shared.models import SigningKey

_jwk_client: PyJWKClient | None = None


def _get_oidc_jwk_client() -> PyJWKClient:
    global _jwk_client
    if _jwk_client is None:
        if not settings.auth_jwks_url:
            raise RuntimeError("AUTH_JWKS_URL is not configured")
        _jwk_client = PyJWKClient(settings.auth_jwks_url)
    return _jwk_client


@dataclass(frozen=True)
class AuthenticatedUser:
    external_id: str  # stable per-user id, namespaced by provider
    email: str | None


def _verify_local(token: str, session: Session) -> AuthenticatedUser:
    if not settings.auth_enable_local:
        raise jwt.InvalidTokenError("local auth provider is disabled")
    header = jwt.get_unverified_header(token)
    kid = header.get("kid")
    signing_key = session.get(SigningKey, kid) if kid else None
    if signing_key is None:
        raise jwt.InvalidTokenError("unknown signing key")
    claims = jwt.decode(
        token,
        signing_key.public_key_pem,
        algorithms=["RS256"],
        audience="authenticated",
        issuer=settings.auth_local_issuer,
    )
    return AuthenticatedUser(external_id=claims["sub"], email=claims.get("email"))


def _verify_oidc(token: str) -> AuthenticatedUser:
    if not settings.auth_enable_oidc:
        raise jwt.InvalidTokenError("OIDC auth provider is disabled")
    signing_key = _get_oidc_jwk_client().get_signing_key_from_jwt(token)
    claims = jwt.decode(
        token,
        signing_key.key,
        algorithms=[a.strip() for a in settings.auth_oidc_algorithms.split(",") if a.strip()],
        audience=settings.auth_oidc_audience,
        issuer=settings.auth_oidc_issuer or None,
    )
    return AuthenticatedUser(external_id=claims["sub"], email=claims.get("email"))


def verify_token(token: str, session: Session) -> AuthenticatedUser:
    """Raises jwt.PyJWTError (or subclasses) on anything invalid/expired/
    disabled — callers translate that to a 401, not a 500."""
    unverified = jwt.decode(token, options={"verify_signature": False})
    if unverified.get("iss") == settings.auth_local_issuer:
        return _verify_local(token, session)
    return _verify_oidc(token)


def get_current_user(
    authorization: str = Header(default=""),
    session: Session = Depends(get_session),
) -> AuthenticatedUser:
    """FastAPI dependency — extracts and verifies the Bearer token."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")

    token = authorization.removeprefix("Bearer ").strip()
    try:
        return verify_token(token, session)
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}") from e
