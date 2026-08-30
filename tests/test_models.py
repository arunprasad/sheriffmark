"""Sanity check: the schema is importable and every expected table
exists. Real behavioral tests (check_limit, tenancy, etc.) land
alongside the code that needs a live DB — see tests/test_limits.py,
tests/test_tenancy.py, tests/test_storage_postgres.py.
"""

from datetime import UTC, datetime

from shared.db import Base, SessionLocal
from shared.models import (  # noqa: F401
    Brand,
    CrawledPage,
    Finding,
    FindingEvent,
    LocalCredential,
    OnDemandScanRequest,
    PageLink,
    Plan,
    RateLimitState,
    ReferenceImage,
    SigningKey,
    Tenant,
    UsageEvent,
    User,
)


def test_all_planned_tables_are_registered():
    expected = {
        "tenants",
        "plans",
        "brands",
        "findings",
        "finding_events",
        "usage_events",
        "users",
        "local_credentials",
        "signing_keys",
        "crawled_pages",
        "page_links",
        "reference_images",
        "rate_limit_state",
        "on_demand_scan_requests",
    }
    assert expected == set(Base.metadata.tables.keys())


def test_utc_datetime_survives_the_round_trip():
    """SQLite's native DateTime has no concept of timezone at all — it
    silently returns a naive datetime on read no matter what was
    written. shared/models.py's UTCDateTime exists specifically to
    reattach UTC on the way out for that case (a no-op on Postgres,
    which never loses it). Every comparison against a stored timestamp
    elsewhere in this codebase assumes it gets back a tz-aware value —
    see worker/pipeline.py's RateLimiter, exercised end to end in
    test_rate_limiter.py."""
    session = SessionLocal()
    try:
        session.add(RateLimitState(resource=f"utc-roundtrip-test-{id(session)}"))
        session.flush()
        state = (
            session.query(RateLimitState)
            .filter_by(resource=f"utc-roundtrip-test-{id(session)}")
            .one()
        )
        assert state.updated_at.tzinfo is not None
        # Doesn't raise "can't compare offset-naive and offset-aware
        # datetimes" — that's the actual failure mode this guards.
        assert state.updated_at <= datetime.now(UTC)
    finally:
        session.rollback()
        session.query(RateLimitState).filter(
            RateLimitState.resource.like("utc-roundtrip-test-%")
        ).delete(synchronize_session=False)
        session.commit()
        session.close()
