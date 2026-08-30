"""First-login tenant bootstrap. A verified auth token proves *who* the
caller is; this maps that identity to *which tenant's data* they can
touch — every other endpoint depends on getting this right.
"""

from fastapi import Depends
from sqlalchemy.orm import Session

from shared.db import get_session
from shared.models import Tenant, User
from web.api.auth import AuthenticatedUser, get_current_user


def get_or_create_tenant(session: Session, user: AuthenticatedUser) -> Tenant:
    """Look up the tenant for this external identity, creating a new
    tenant on the `free` plan on first login. This is the one place a
    `tenants` row gets created from the web app (`worker/seed.py` is the
    only other place, for local dev)."""
    existing = session.get(User, user.external_id)
    if existing is not None:
        return existing.tenant

    tenant = Tenant(name=user.email or user.external_id, plan_id="free")
    session.add(tenant)
    session.flush()  # need tenant.tenant_id before creating the User row

    membership = User(external_id=user.external_id, tenant_id=tenant.tenant_id, role="owner")
    session.add(membership)
    session.commit()

    return tenant


def get_current_tenant(
    user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> Tenant:
    """The dependency routes actually use — verifies the token and
    resolves/creates the tenant in one step."""
    return get_or_create_tenant(session, user)
