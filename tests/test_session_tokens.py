import jwt
import pytest

from shared.config import settings
from shared.db import SessionLocal
from shared.models import SigningKey
from web.api.session_tokens import issue_token


@pytest.fixture
def session():
    s = SessionLocal()
    yield s
    s.rollback()
    s.query(SigningKey).delete()
    s.commit()
    s.close()


def test_issued_token_carries_expected_claims_and_verifies_against_the_stored_key(session):
    token = issue_token(session, external_id="local:1", email="a@example.com")

    key = session.query(SigningKey).one()
    claims = jwt.decode(
        token,
        key.public_key_pem,
        algorithms=["RS256"],
        audience="authenticated",
        issuer=settings.auth_local_issuer,
    )

    assert claims["sub"] == "local:1"
    assert claims["email"] == "a@example.com"


def test_two_issuances_reuse_the_same_signing_key(session):
    issue_token(session, external_id="local:1", email="a@example.com")
    issue_token(session, external_id="local:2", email="b@example.com")

    assert session.query(SigningKey).count() == 1
