"""Manually seed one tenant + one brand, for end-to-end testing of the
worker pipeline against a real (local) Postgres. Idempotent — safe to
re-run; matches on tenant name.

Usage:
    docker compose up -d postgres
    alembic upgrade head
    python -m worker.seed
    python -m worker.main
"""

from shared.db import SessionLocal
from shared.models import Brand, Tenant

SEED_TENANT_NAME = "Acme Test Co"
SEED_TENANT_EMAIL = "findarunhere@gmail.com"  # replace with a real inbox you can check
SEED_BRAND_NAME = "acmecorp"


def seed() -> None:
    session = SessionLocal()
    try:
        tenant = session.query(Tenant).filter_by(name=SEED_TENANT_NAME).one_or_none()
        if tenant is None:
            tenant = Tenant(name=SEED_TENANT_NAME, plan_id="free", contact_email=SEED_TENANT_EMAIL)
            session.add(tenant)
            session.flush()
            print(f"created tenant {tenant.tenant_id}")
        else:
            print(f"tenant already exists: {tenant.tenant_id}")

        brand = (
            session.query(Brand)
            .filter_by(tenant_id=tenant.tenant_id, name=SEED_BRAND_NAME)
            .one_or_none()
        )
        if brand is None:
            brand = Brand(
                tenant_id=tenant.tenant_id,
                name=SEED_BRAND_NAME,
                keywords=["billing"],
                tlds=["com", "net"],
                variant_rules=[],
                active=True,
            )
            session.add(brand)
            print(f"created brand {SEED_BRAND_NAME}")
        else:
            print(f"brand already exists: {brand.brand_id}")

        session.commit()
    finally:
        session.close()


if __name__ == "__main__":
    seed()
