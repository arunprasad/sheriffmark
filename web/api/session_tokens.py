"""Issues this server's own session JWTs — shared by the local
email/password provider (web/api/local_auth.py) and the SAML SP
(web/api/saml_auth.py). Both end a login the same way: a user identity
has just been established (by password check or by a validated SAML
assertion), and the browser needs a Bearer token it can use against the
API. Verification of these tokens lives in web/api/auth.py.
"""

from datetime import UTC, datetime, timedelta

import jwt
from sqlalchemy.orm import Session

from shared.config import settings
from web.api.crypto_keys import get_or_create_signing_key

TOKEN_TTL = timedelta(hours=24)


def issue_token(session: Session, external_id: str, email: str | None) -> str:
    signing_key = get_or_create_signing_key(session)
    now = datetime.now(UTC)
    claims = {
        "sub": external_id,
        "email": email,
        "iss": settings.auth_local_issuer,
        "aud": "authenticated",
        "iat": now,
        "exp": now + TOKEN_TTL,
    }
    return jwt.encode(
        claims,
        signing_key.private_key_pem,
        algorithm="RS256",
        headers={"kid": signing_key.kid},
    )
