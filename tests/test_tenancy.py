"""Real-DB tests — tenant auto-provisioning is exactly the kind of logic
(first-login race, relationship correctness) that's worth verifying
against a real session rather than mocks.
"""

import uuid

import pytest

from shared.db import SessionLocal
from shared.models import Tenant, User
from web.api.auth import AuthenticatedUser
from web.api.tenancy import get_or_create_tenant


@pytest.fixture
def session():
    s = SessionLocal()
    yield s
    s.rollback()
    s.close()


def _cleanup(session, external_id, tenant_id):
    session.query(User).filter_by(external_id=external_id).delete()
    session.query(Tenant).filter_by(tenant_id=tenant_id).delete()
    session.commit()


class TestGetOrCreateTenant:
    def test_first_login_creates_tenant_and_membership(self, session):
        user = AuthenticatedUser(external_id=f"auth-{uuid.uuid4()}", email="new@example.com")

        tenant = get_or_create_tenant(session, user)
        try:
            assert tenant.plan_id == "free"
            assert tenant.name == "new@example.com"

            membership = session.get(User, user.external_id)
            assert membership is not None
            assert membership.tenant_id == tenant.tenant_id
            assert membership.role == "owner"
        finally:
            _cleanup(session, user.external_id, tenant.tenant_id)

    def test_second_login_returns_same_tenant_not_a_duplicate(self, session):
        user = AuthenticatedUser(external_id=f"auth-{uuid.uuid4()}", email="repeat@example.com")

        first = get_or_create_tenant(session, user)
        try:
            second = get_or_create_tenant(session, user)
            assert first.tenant_id == second.tenant_id
        finally:
            _cleanup(session, user.external_id, first.tenant_id)
