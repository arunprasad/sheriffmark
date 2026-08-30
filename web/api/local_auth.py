"""Local email/password provider: account creation, authentication, and
JWT issuance. Verification against these tokens happens in
web/api/auth.py, which routes any incoming token to this provider or to
the external OIDC provider by inspecting its issuer claim.
"""

import secrets
import uuid
from dataclasses import dataclass

import bcrypt
from sqlalchemy import select
from sqlalchemy.orm import Session

from shared.config import settings
from shared.models import LocalCredential


class EmailAlreadyRegistered(Exception):
    pass


class InvalidCredentials(Exception):
    pass


class EmailNotVerified(Exception):
    pass


class AccountNotFound(Exception):
    pass


def _hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def _verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), password_hash.encode())


@dataclass(frozen=True)
class RegisterResult:
    credential: LocalCredential
    verification_token: str | None  # set only when SMTP is configured


def register(
    session: Session, email: str, password: str, *, auto_verify: bool = False
) -> RegisterResult:
    """`auto_verify` bypasses the SMTP-gated verification step
    regardless of Settings.smtp_configured — used by the admin CLI
    (web/api/manage.py) to bootstrap an immediately-usable account
    without depending on SMTP being wired up yet."""
    email = email.strip().lower()
    existing = session.execute(
        select(LocalCredential).where(LocalCredential.email == email)
    ).scalar_one_or_none()
    if existing is not None:
        raise EmailAlreadyRegistered(email)

    needs_verification = settings.smtp_configured and not auto_verify
    verification_token = secrets.token_urlsafe(32) if needs_verification else None
    credential = LocalCredential(
        external_id=f"local:{uuid.uuid4()}",
        email=email,
        password_hash=_hash_password(password),
        email_verified=not needs_verification,
        verification_token=verification_token,
    )
    session.add(credential)
    session.commit()
    return RegisterResult(credential=credential, verification_token=verification_token)


def authenticate(session: Session, email: str, password: str) -> LocalCredential:
    email = email.strip().lower()
    credential = session.execute(
        select(LocalCredential).where(LocalCredential.email == email)
    ).scalar_one_or_none()
    if credential is None or not _verify_password(password, credential.password_hash):
        raise InvalidCredentials(email)
    if not credential.email_verified:
        raise EmailNotVerified(email)
    return credential


def set_password(
    session: Session, email: str, password: str, *, verify: bool = False
) -> LocalCredential:
    """Directly overwrites an existing account's password, bypassing
    the normal login flow entirely — used by the admin CLI
    (web/api/manage.py) for account recovery when a caller has database
    access but no working login (self-hosted deployments have no other
    password-reset path today). `verify=True` also marks the account
    verified and clears any pending token, so a CLI-driven reset
    unblocks a previously-unverified account too."""
    email = email.strip().lower()
    credential = session.execute(
        select(LocalCredential).where(LocalCredential.email == email)
    ).scalar_one_or_none()
    if credential is None:
        raise AccountNotFound(email)

    credential.password_hash = _hash_password(password)
    if verify:
        credential.email_verified = True
        credential.verification_token = None
    session.commit()
    return credential


def verify_email(session: Session, token: str) -> LocalCredential:
    credential = session.execute(
        select(LocalCredential).where(LocalCredential.verification_token == token)
    ).scalar_one_or_none()
    if credential is None:
        raise InvalidCredentials(token)
    credential.email_verified = True
    credential.verification_token = None
    session.commit()
    return credential


