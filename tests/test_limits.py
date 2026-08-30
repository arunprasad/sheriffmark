"""Real-DB tests — check_limit reads live relationships (tenant.plan,
tenant.brands), so it's tested against a real session rather than mocks.
"""

import uuid

import pytest

from shared.db import SessionLocal
from shared.limits import check_limit
from shared.models import Brand, Plan, Tenant


@pytest.fixture
def session():
    s = SessionLocal()
    yield s
    s.rollback()
    s.close()


@pytest.fixture
def capped_plan(session):
    plan = Plan(
        plan_id=f"test-capped-{uuid.uuid4().hex[:8]}",
        name="Test Capped",
        limits={"max_brands": 1},
    )
    session.add(plan)
    session.flush()
    yield plan
    session.query(Plan).filter_by(plan_id=plan.plan_id).delete()
    session.commit()


class TestCheckLimitBrandCreate:
    def test_under_limit_permits(self, session, capped_plan):
        tenant = Tenant(name="Under Limit Co", plan_id=capped_plan.plan_id)
        session.add(tenant)
        session.flush()

        try:
            assert check_limit(tenant, "brand_create") is True
        finally:
            session.query(Tenant).filter_by(tenant_id=tenant.tenant_id).delete()
            session.commit()

    def test_at_limit_denies(self, session, capped_plan):
        tenant = Tenant(name="At Limit Co", plan_id=capped_plan.plan_id)
        session.add(tenant)
        session.flush()
        session.add(
            Brand(
                tenant_id=tenant.tenant_id,
                name="already-have-one",
                keywords=[],
                tlds=["com"],
                variant_rules=[],
                active=True,
            )
        )
        session.commit()
        session.refresh(tenant)

        try:
            assert check_limit(tenant, "brand_create") is False
        finally:
            session.query(Brand).filter_by(tenant_id=tenant.tenant_id).delete()
            session.query(Tenant).filter_by(tenant_id=tenant.tenant_id).delete()
            session.commit()

    def test_no_max_brands_key_means_unlimited(self, session):
        unlimited_plan = Plan(
            plan_id=f"test-unlimited-{uuid.uuid4().hex[:8]}", name="Unlimited", limits={}
        )
        session.add(unlimited_plan)
        session.flush()
        tenant = Tenant(name="Unlimited Co", plan_id=unlimited_plan.plan_id)
        session.add(tenant)
        session.flush()

        try:
            assert check_limit(tenant, "brand_create") is True
        finally:
            session.query(Tenant).filter_by(tenant_id=tenant.tenant_id).delete()
            session.query(Plan).filter_by(plan_id=unlimited_plan.plan_id).delete()
            session.commit()

    def test_unknown_resource_permits_by_default(self, session, capped_plan):
        tenant = Tenant(name="Whatever Co", plan_id=capped_plan.plan_id)
        session.add(tenant)
        session.flush()

        try:
            assert check_limit(tenant, "some_future_resource") is True
        finally:
            session.query(Tenant).filter_by(tenant_id=tenant.tenant_id).delete()
            session.commit()
