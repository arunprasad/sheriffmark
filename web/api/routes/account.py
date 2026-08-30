"""Account-level settings — notification channels and contact email
live on `Tenant`, not `Brand`, so they're shared across every brand a
tenant has rather than configured per-brand. Previously had no API at
all (only ever set via `worker/seed.py` for local dev); this is the
console redesign's "Account" area, sibling to the brand index page,
not nested under any single brand's Settings tab.
"""

import uuid

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from shared.db import get_session
from shared.models import Tenant
from web.api.tenancy import get_current_tenant

router = APIRouter(prefix="/api/account", tags=["account"])


class AccountOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    tenant_id: uuid.UUID
    name: str
    contact_email: str | None
    # Keys: "slack_webhook_url", "discord_webhook_url", "webhook_url" —
    # a missing/empty key means that channel isn't configured. See
    # worker/pipeline.py's dispatch_notifications.
    notification_channels: dict


class AccountUpdateIn(BaseModel):
    contact_email: str | None = None
    # Merged into the existing dict, not replaced wholesale — a caller
    # updating just the Slack URL shouldn't have to resend Discord's
    # and the plain webhook's to avoid wiping them.
    notification_channels: dict | None = None


@router.get("", response_model=AccountOut)
def get_account(tenant: Tenant = Depends(get_current_tenant)) -> Tenant:
    return tenant


@router.patch("", response_model=AccountOut)
def update_account(
    payload: AccountUpdateIn,
    tenant: Tenant = Depends(get_current_tenant),
    session: Session = Depends(get_session),
) -> Tenant:
    updates = payload.model_dump(exclude_unset=True)
    if "notification_channels" in updates:
        tenant.notification_channels = {
            **tenant.notification_channels,
            **updates.pop("notification_channels"),
        }
    for field, value in updates.items():
        setattr(tenant, field, value)
    session.commit()
    session.refresh(tenant)
    return tenant
