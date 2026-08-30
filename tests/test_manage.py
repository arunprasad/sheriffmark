"""Tests for the admin CLI's core logic (web/api/manage.py). The
interactive password prompt (_prompt_password, getpass-based) is
deliberately not unit-tested here — create_account/reset_password take
the password as a plain argument precisely so the account-creation/
recovery logic is testable without mocking stdin."""

import sys
from unittest.mock import patch

import pytest

from shared.db import SessionLocal
from shared.models import LocalCredential
from web.api import local_auth, manage


@pytest.fixture
def session():
    s = SessionLocal()
    yield s
    s.rollback()
    s.query(LocalCredential).delete()
    s.commit()
    s.close()


class TestCreateAccount:
    def test_creates_an_immediately_usable_account(self, session, capsys):
        manage.create_account("cli@example.com", "password123")

        out = capsys.readouterr().out
        assert "Account created" in out
        credential = local_auth.authenticate(session, "cli@example.com", "password123")
        assert credential.email_verified is True

    def test_existing_email_exits_with_an_error(self, session, capsys):
        local_auth.register(session, "dupe@example.com", "password123", auto_verify=True)

        with pytest.raises(SystemExit) as exc_info:
            manage.create_account("dupe@example.com", "password456")

        assert exc_info.value.code == 1
        assert "already registered" in capsys.readouterr().err


class TestResetPassword:
    def test_resets_and_verifies_an_existing_account(self, session, capsys):
        local_auth.register(session, "a@example.com", "old-password", auto_verify=True)

        manage.reset_password("a@example.com", "new-password-456")

        out = capsys.readouterr().out
        assert "Password reset" in out
        local_auth.authenticate(session, "a@example.com", "new-password-456")

    def test_unblocks_a_previously_unverified_account(self, session, capsys):
        from shared.config import settings

        with patch.object(settings, "smtp_host", "smtp.example.com"):
            local_auth.register(session, "a@example.com", "old-password")

        manage.reset_password("a@example.com", "new-password-456")

        credential = local_auth.authenticate(session, "a@example.com", "new-password-456")
        assert credential.email_verified is True

    def test_unknown_email_exits_with_an_error(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            manage.reset_password("nobody@example.com", "new-password-456")

        assert exc_info.value.code == 1
        assert "no account found" in capsys.readouterr().err


class TestPromptPassword:
    def test_mismatched_passwords_exit_with_an_error(self, capsys):
        with patch("web.api.manage.getpass.getpass", side_effect=["pw-one", "pw-two"]):
            with pytest.raises(SystemExit) as exc_info:
                manage._prompt_password()

        assert exc_info.value.code == 1
        assert "do not match" in capsys.readouterr().err

    def test_short_password_exits_with_an_error(self, capsys):
        with patch("web.api.manage.getpass.getpass", side_effect=["short", "short"]):
            with pytest.raises(SystemExit) as exc_info:
                manage._prompt_password()

        assert exc_info.value.code == 1
        assert "at least 8 characters" in capsys.readouterr().err

    def test_matching_valid_password_is_returned(self):
        with patch("web.api.manage.getpass.getpass", side_effect=["password123", "password123"]):
            assert manage._prompt_password() == "password123"


class TestMain:
    def test_create_account_subcommand_wires_through(self, session, capsys):
        argv = ["create-account", "cli@example.com"]
        with patch("web.api.manage.getpass.getpass", side_effect=["password123", "password123"]):
            manage.main(argv)

        assert "Account created" in capsys.readouterr().out

    def test_missing_subcommand_exits_nonzero(self):
        with patch.object(sys, "argv", ["manage.py"]):
            with pytest.raises(SystemExit) as exc_info:
                manage.main([])

        assert exc_info.value.code != 0
