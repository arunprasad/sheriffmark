import pytest

from shared.db import SessionLocal
from shared.models import SigningKey
from web.api.crypto_keys import get_or_create_signing_key


@pytest.fixture
def session():
    s = SessionLocal()
    yield s
    s.rollback()
    s.query(SigningKey).delete()
    s.commit()
    s.close()


def test_creates_a_key_when_none_exists(session):
    key = get_or_create_signing_key(session)

    assert key.kid
    assert "BEGIN PRIVATE KEY" in key.private_key_pem
    assert "BEGIN PUBLIC KEY" in key.public_key_pem


def test_reuses_the_existing_key_on_subsequent_calls(session):
    first = get_or_create_signing_key(session)
    second = get_or_create_signing_key(session)

    assert first.kid == second.kid
    assert session.query(SigningKey).count() == 1
