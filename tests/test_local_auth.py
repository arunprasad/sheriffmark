from unittest.mock import patch

import pytest

from shared.config import settings
from shared.db import SessionLocal
from shared.models import LocalCredential
from web.api import local_auth


@pytest.fixture
def session():
    s = SessionLocal()
    yield s
    s.rollback()
    s.query(LocalCredential).delete()
    s.commit()
    s.close()


class TestRegister:
    def test_creates_an_auto_verified_account_when_smtp_is_not_configured(self, session):
        with patch.object(settings, "smtp_host", ""):
            result = local_auth.register(session, "New@Example.com", "password123")

        assert result.verification_token is None
        assert result.credential.email == "new@example.com"  # normalized
        assert result.credential.email_verified is True
        assert result.credential.external_id.startswith("local:")

    def test_creates_an_unverified_account_with_a_token_when_smtp_is_configured(self, session):
        with patch.object(settings, "smtp_host", "smtp.example.com"):
            result = local_auth.register(session, "a@example.com", "password123")

        assert result.verification_token is not None
        assert result.credential.email_verified is False
        assert result.credential.verification_token == result.verification_token

    def test_duplicate_email_is_rejected(self, session):
        with patch.object(settings, "smtp_host", ""):
            local_auth.register(session, "dupe@example.com", "password123")
            with pytest.raises(local_auth.EmailAlreadyRegistered):
                local_auth.register(session, "DUPE@example.com", "password123")

    def test_auto_verify_bypasses_the_smtp_gate(self, session):
        """The admin CLI (web/api/manage.py) needs a usable account
        immediately, regardless of whether SMTP happens to be
        configured on this deployment."""
        with patch.object(settings, "smtp_host", "smtp.example.com"):
            result = local_auth.register(
                session, "cli@example.com", "password123", auto_verify=True
            )

        assert result.verification_token is None
        assert result.credential.email_verified is True
        local_auth.authenticate(session, "cli@example.com", "password123")


class TestAuthenticate:
    def test_correct_password_succeeds(self, session):
        with patch.object(settings, "smtp_host", ""):
            local_auth.register(session, "a@example.com", "password123")

        credential = local_auth.authenticate(session, "a@example.com", "password123")

        assert credential.email == "a@example.com"

    def test_wrong_password_raises(self, session):
        with patch.object(settings, "smtp_host", ""):
            local_auth.register(session, "a@example.com", "password123")

        with pytest.raises(local_auth.InvalidCredentials):
            local_auth.authenticate(session, "a@example.com", "wrong-password")

    def test_unknown_email_raises(self, session):
        with pytest.raises(local_auth.InvalidCredentials):
            local_auth.authenticate(session, "nobody@example.com", "password123")

    def test_unverified_account_raises(self, session):
        with patch.object(settings, "smtp_host", "smtp.example.com"):
            local_auth.register(session, "a@example.com", "password123")

        with pytest.raises(local_auth.EmailNotVerified):
            local_auth.authenticate(session, "a@example.com", "password123")


class TestVerifyEmail:
    def test_valid_token_marks_verified_and_clears_the_token(self, session):
        with patch.object(settings, "smtp_host", "smtp.example.com"):
            result = local_auth.register(session, "a@example.com", "password123")

        credential = local_auth.verify_email(session, result.verification_token)

        assert credential.email_verified is True
        assert credential.verification_token is None
        # now unblocked
        local_auth.authenticate(session, "a@example.com", "password123")

    def test_unknown_token_raises(self, session):
        with pytest.raises(local_auth.InvalidCredentials):
            local_auth.verify_email(session, "not-a-real-token")


class TestSetPassword:
    """Direct password overwrite — the admin CLI's (web/api/manage.py)
    recovery path for a self-hoster with database access but no working
    login, since there's no other password-reset flow."""

    def test_overwrites_the_password_hash(self, session):
        with patch.object(settings, "smtp_host", ""):
            local_auth.register(session, "a@example.com", "password123")

        local_auth.set_password(session, "A@Example.com", "new-password-456")

        with pytest.raises(local_auth.InvalidCredentials):
            local_auth.authenticate(session, "a@example.com", "password123")
        credential = local_auth.authenticate(session, "a@example.com", "new-password-456")
        assert credential.email == "a@example.com"

    def test_verify_flag_unblocks_a_previously_unverified_account(self, session):
        with patch.object(settings, "smtp_host", "smtp.example.com"):
            local_auth.register(session, "a@example.com", "password123")

        local_auth.set_password(session, "a@example.com", "new-password-456", verify=True)

        credential = local_auth.authenticate(session, "a@example.com", "new-password-456")
        assert credential.email_verified is True
        assert credential.verification_token is None

    def test_without_verify_flag_leaves_verification_state_untouched(self, session):
        with patch.object(settings, "smtp_host", "smtp.example.com"):
            local_auth.register(session, "a@example.com", "password123")

        local_auth.set_password(session, "a@example.com", "new-password-456")

        with pytest.raises(local_auth.EmailNotVerified):
            local_auth.authenticate(session, "a@example.com", "new-password-456")

    def test_unknown_email_raises(self, session):
        with pytest.raises(local_auth.AccountNotFound):
            local_auth.set_password(session, "nobody@example.com", "new-password-456")
