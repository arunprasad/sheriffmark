"""Integration tests against a real DB (SQLite by default, Postgres if
configured — see test_storage_postgres.py) for worker.pipeline's
RateLimiter — same discipline as test_storage_postgres.py: no mocking,
since the whole point is "does a suspension persisted by one instance
get honored by a fresh one," which a mocked session can't prove. Also
exercises shared/models.py's UTCDateTime round-trip: RateLimiter's own
`is_active()` compares a stored `suspended_until` against
`datetime.now(UTC)`, which would raise (naive vs. aware) if that fix
ever regressed on SQLite.
"""

from datetime import UTC, datetime

import pytest

from shared.db import SessionLocal
from shared.models import RateLimitState
from worker.pipeline import DEFAULT_RATE_LIMIT_BACKOFF_SECONDS, RateLimiter


@pytest.fixture
def session():
    s = SessionLocal()
    yield s
    s.rollback()
    s.query(RateLimitState).delete()
    s.commit()
    s.close()


class TestRateLimiter:
    def test_not_active_when_nothing_recorded(self, session):
        limiter = RateLimiter(session, "rdap")
        assert limiter.is_active() is False

    def test_trip_makes_it_active_immediately(self, session):
        limiter = RateLimiter(session, "rdap")
        limiter.trip(retry_after_seconds=60)
        assert limiter.is_active() is True

    def test_trip_without_retry_after_uses_the_default_backoff(self, session):
        # Python-side timestamp only, deliberately not compared against
        # any server-computed column — a cross-clock-source comparison
        # here would just be testing clock sync, not this logic.
        before = datetime.now(UTC)

        limiter = RateLimiter(session, "rdap")
        limiter.trip(retry_after_seconds=None)
        session.commit()

        state = session.get(RateLimitState, "rdap")
        delta = (state.suspended_until - before).total_seconds()
        assert abs(delta - DEFAULT_RATE_LIMIT_BACKOFF_SECONDS) < 5

    def test_suspension_persists_across_instances(self, session):
        """The actual point of this class — a suspension from one
        worker invocation must be honored by the next, not just for
        the rest of the tripping instance's own lifetime."""
        RateLimiter(session, "rdap").trip(retry_after_seconds=60)
        session.commit()

        fresh_limiter = RateLimiter(session, "rdap")
        assert fresh_limiter.is_active() is True

    def test_expired_suspension_is_not_active(self, session):
        RateLimiter(session, "rdap").trip(retry_after_seconds=-10)  # already in the past
        session.commit()

        assert RateLimiter(session, "rdap").is_active() is False

    def test_resources_are_independent(self, session):
        RateLimiter(session, "rdap").trip(retry_after_seconds=60)
        session.commit()

        assert RateLimiter(session, "ct").is_active() is False

    def test_retripping_updates_the_existing_row_not_a_duplicate(self, session):
        RateLimiter(session, "rdap").trip(retry_after_seconds=60)
        session.commit()
        RateLimiter(session, "rdap").trip(retry_after_seconds=120)
        session.commit()

        assert session.query(RateLimitState).filter_by(resource="rdap").count() == 1
