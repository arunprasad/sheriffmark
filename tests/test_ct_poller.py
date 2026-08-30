from unittest.mock import MagicMock, patch

import requests

from core.ct_poller import CTPollResult, poll_ct_logs


def test_returns_only_entries_newer_than_cursor():
    session = MagicMock()
    session.get.return_value = MagicMock(
        status_code=200,
        json=lambda: [
            {"id": 100, "common_name": "old.example.com", "entry_timestamp": "2020-01-01T00:00:00"},
            {"id": 200, "common_name": "new.example.com", "entry_timestamp": "2021-01-01T00:00:00"},
        ],
        raise_for_status=lambda: None,
    )

    result = poll_ct_logs("example", since_cert_id=150, session=session)

    assert result.success is True
    assert [h.cert_id for h in result.hits] == [200]
    assert result.max_cert_id == 200


def test_no_new_entries_still_advances_nothing_but_succeeds():
    session = MagicMock()
    session.get.return_value = MagicMock(
        status_code=200,
        json=lambda: [{"id": 50, "common_name": "old.example.com", "entry_timestamp": None}],
        raise_for_status=lambda: None,
    )

    result = poll_ct_logs("example", since_cert_id=100, session=session)

    assert result == CTPollResult(success=True, hits=[], max_cert_id=100)


def test_crtsh_outage_fails_closed_not_an_exception():
    """crt.sh returning a 502 is a real, reproducible occurrence — hit
    at least four separate times across this project's own development
    — must degrade gracefully, not raise, and must not be confused with
    'no new certs found'. retries=1 here to test the fail-closed
    behavior itself without exercising the (separately tested)
    retry/backoff loop."""
    session = MagicMock()
    response = MagicMock(status_code=502)
    response.raise_for_status.side_effect = requests.HTTPError("502 Bad Gateway")
    session.get.return_value = response

    result = poll_ct_logs("example", since_cert_id=0, session=session, retries=1)

    assert result.success is False
    assert result.hits == []
    assert result.max_cert_id is None


def test_malformed_json_fails_closed():
    session = MagicMock()
    session.get.return_value = MagicMock(
        status_code=200,
        raise_for_status=lambda: None,
        json=MagicMock(side_effect=ValueError("not json")),
    )

    result = poll_ct_logs("example", session=session, retries=1)

    assert result.success is False


class TestRateLimit:
    def test_429_is_distinguished_from_other_failures(self):
        """Distinct from the generic outage path — retrying immediately
        into a rate limit doesn't help the way retrying a transient 502
        does, so this returns immediately rather than consuming
        `retries` attempts."""
        session = MagicMock()
        session.get.return_value = MagicMock(status_code=429, headers={"Retry-After": "60"})

        result = poll_ct_logs("example", session=session, retries=3)

        assert result.success is False
        assert result.rate_limited is True
        assert result.retry_after_seconds == 60.0
        session.get.assert_called_once()  # no retry storm against a service that just throttled us

    def test_429_without_retry_after_header(self):
        session = MagicMock()
        session.get.return_value = MagicMock(status_code=429, headers={})

        result = poll_ct_logs("example", session=session)

        assert result.rate_limited is True
        assert result.retry_after_seconds is None


class TestRetryWithBackoff:
    @patch("core.ct_poller.time.sleep")
    def test_succeeds_on_second_attempt_after_transient_failure(self, mock_sleep):
        """The exact scenario this feature exists for: crt.sh blips once
        (a 502) and recovers within the same poll — should not cost a
        whole day's CT coverage."""
        session = MagicMock()
        failing_response = MagicMock(status_code=502)
        failing_response.raise_for_status.side_effect = requests.HTTPError("502")
        succeeding_response = MagicMock(
            status_code=200,
            raise_for_status=lambda: None,
            json=lambda: [{"id": 1, "common_name": "new.example.com", "entry_timestamp": None}],
        )
        session.get.side_effect = [failing_response, succeeding_response]

        result = poll_ct_logs("example", session=session, retries=3)

        assert result.success is True
        assert len(result.hits) == 1
        assert session.get.call_count == 2
        mock_sleep.assert_called_once()

    @patch("core.ct_poller.time.sleep")
    def test_exhausts_all_retries_before_giving_up(self, mock_sleep):
        session = MagicMock()
        response = MagicMock(status_code=502)
        response.raise_for_status.side_effect = requests.HTTPError("502")
        session.get.return_value = response

        result = poll_ct_logs("example", session=session, retries=3, backoff_seconds=0.01)

        assert result.success is False
        assert session.get.call_count == 3
        assert mock_sleep.call_count == 2  # backs off between attempts, not after the last

    @patch("core.ct_poller.time.sleep")
    def test_backoff_increases_linearly(self, mock_sleep):
        session = MagicMock()
        response = MagicMock(status_code=502)
        response.raise_for_status.side_effect = requests.HTTPError("502")
        session.get.return_value = response

        poll_ct_logs("example", session=session, retries=3, backoff_seconds=2.0)

        mock_sleep.assert_any_call(2.0)  # after attempt 1
        mock_sleep.assert_any_call(4.0)  # after attempt 2
