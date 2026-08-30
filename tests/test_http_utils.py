from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

from shared.http_utils import parse_retry_after


class TestParseRetryAfter:
    def test_none_returns_none(self):
        assert parse_retry_after(None) is None

    def test_empty_string_returns_none(self):
        assert parse_retry_after("") is None

    def test_plain_integer_seconds(self):
        assert parse_retry_after("120") == 120.0

    def test_plain_float_seconds(self):
        assert parse_retry_after("2.5") == 2.5

    def test_negative_seconds_is_clamped_to_zero(self):
        assert parse_retry_after("-5") == 0.0

    def test_http_date_in_the_future(self):
        target = datetime.now(UTC) + timedelta(seconds=60)
        raw = format_datetime(target, usegmt=True)

        result = parse_retry_after(raw)

        assert result is not None
        assert 55 <= result <= 65  # allow a little slack for test execution time

    def test_http_date_in_the_past_is_clamped_to_zero(self):
        target = datetime.now(UTC) - timedelta(seconds=60)
        raw = format_datetime(target, usegmt=True)

        assert parse_retry_after(raw) == 0.0

    def test_garbage_value_returns_none(self):
        assert parse_retry_after("not a valid retry-after value") is None
