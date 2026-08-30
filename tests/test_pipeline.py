"""Pipeline orchestration tests. Storage and core calls are mocked at the
worker.pipeline import site — this tests *decisions* (what counts as new,
which path failing shouldn't affect the other, when a digest gets sent),
not the DB or network behavior those pieces have their own tests for.
"""

from contextlib import ExitStack
from datetime import UTC, datetime, timedelta
from unittest.mock import ANY, MagicMock, patch

from core.crawler import WebsiteSnapshot
from core.ct_poller import CertHit, CTPollResult
from core.dns_snapshot import DnsSnapshot
from core.registration import RegistrationStatus
from core.site_graph import SiteGraph
from core.variants import Candidate
from worker.pipeline import (
    BLOCKLIST_RISK_BONUS,
    MAX_SCAN_AGE,
    _is_scan_stale,
    _record_finding,
    dispatch_notifications,
    process_brand_ct,
    process_brand_custom,
    process_brand_generated,
    process_tenant,
    run_daily_pipeline,
    run_on_demand_scan,
)


def make_brand(**overrides):
    brand = MagicMock()
    brand.brand_id = "brand-1"
    brand.name = "acme"
    brand.keywords = ["billing"]
    brand.tlds = ["com"]
    brand.active = True
    brand.ct_last_cert_id = None
    brand.custom_domains = []
    brand.owned_domains = []
    brand.generated_scan_cursor = None
    brand.custom_scan_cursor = None
    brand.generated_scan_started_at = None
    brand.custom_scan_started_at = None
    brand.last_scan_completed_at = None
    for key, value in overrides.items():
        setattr(brand, key, value)
    return brand


class TestIsScanStale:
    def test_none_is_never_stale(self):
        assert _is_scan_stale(None) is False

    def test_within_the_window_is_not_stale(self):
        assert _is_scan_stale(datetime.now(UTC) - timedelta(hours=1)) is False

    def test_past_the_window_is_stale(self):
        assert _is_scan_stale(datetime.now(UTC) - (MAX_SCAN_AGE + timedelta(minutes=1))) is True

    def test_exactly_at_the_boundary_is_not_yet_stale(self):
        # Strictly greater-than in the implementation — right at the
        # boundary should still count as fresh.
        assert _is_scan_stale(datetime.now(UTC) - MAX_SCAN_AGE + timedelta(seconds=5)) is False


class TestProcessBrandGenerated:
    """Orchestration only — treats `_record_finding` as a black box (its
    own diff/event/notability logic is covered in depth by
    TestRecordFinding below). These tests check: does this path only
    call `_record_finding` for registered candidates, and does it
    correctly interpret the (is_new, had_incidents) it gets back?"""

    @patch("worker.pipeline._record_finding")
    @patch("worker.pipeline.has_mx_records", return_value=False)
    @patch("worker.pipeline.check_registration")
    @patch("worker.pipeline.load_tld_nameservers", return_value=[("ns1.", "1.2.3.4")])
    @patch("worker.pipeline.load_tld_whois_host", return_value=None)
    @patch("worker.pipeline.generate_variants")
    def test_only_registered_candidates_become_findings(
        self, mock_gen, mock_whois, mock_ns, mock_check, mock_mx, mock_record
    ):
        mock_gen.return_value = [
            Candidate("acme-login.com", "dictionary"),
            Candidate("acmee.com", "omission"),
        ]
        mock_check.side_effect = [
            RegistrationStatus(status="registered", registrar="GoDaddy"),
            RegistrationStatus(status="unregistered"),
        ]
        mock_record.return_value = (MagicMock(risk_score=50), True, False)

        results = process_brand_generated(MagicMock(), make_brand())

        assert len(results) == 1
        assert results[0].domain == "acme-login.com"
        mock_record.assert_called_once()  # unregistered candidate never reaches _record_finding

    @patch("worker.pipeline.generate_variants", side_effect=RuntimeError("boom"))
    def test_variant_generation_failure_does_not_raise(self, _mock_gen):
        results = process_brand_generated(MagicMock(), make_brand())
        assert results == []

    @patch("worker.pipeline._record_finding")
    @patch("worker.pipeline.has_mx_records", return_value=False)
    @patch(
        "worker.pipeline.check_registration",
        return_value=RegistrationStatus(
            status="registered", registrar="GoDaddy", abuse_email="abuse@registrar.test"
        ),
    )
    @patch("worker.pipeline.load_tld_nameservers", return_value=[("ns1.", "1.2.3.4")])
    @patch("worker.pipeline.load_tld_whois_host", return_value=None)
    @patch("worker.pipeline.generate_variants")
    def test_abuse_email_flows_through_to_record_finding(
        self, mock_gen, mock_whois, mock_ns, mock_check, mock_mx, mock_record
    ):
        mock_gen.return_value = [Candidate("acme-login.com", "dictionary")]
        mock_record.return_value = (MagicMock(risk_score=50), True, False)

        process_brand_generated(MagicMock(), make_brand())

        _, kwargs = mock_record.call_args
        assert kwargs["abuse_email"] == "abuse@registrar.test"

    @patch("worker.pipeline._record_finding")
    @patch("worker.pipeline.has_mx_records", return_value=False)
    @patch(
        "worker.pipeline.check_registration",
        return_value=RegistrationStatus(status="registered"),
    )
    @patch("worker.pipeline.load_tld_nameservers", return_value=[("ns1.", "1.2.3.4")])
    @patch("worker.pipeline.load_tld_whois_host", return_value=None)
    @patch("worker.pipeline.generate_variants")
    def test_digest_summary_reflects_a_blocklist_bump_not_the_pre_bump_score(
        self, mock_gen, mock_whois, mock_ns, mock_check, mock_mx, mock_record
    ):
        """_record_finding can raise the score above what this
        function itself computed (an IP-blocklist hit, only knowable
        once DNS is acquired inside it) — the digest must report the
        finding's actual final score, not the stale pre-bump one."""
        mock_gen.return_value = [Candidate("acme-login.com", "dictionary")]
        # Whatever score this test's own RiskFactors would compute,
        # _record_finding's return is what actually landed in storage
        # — here, deliberately different (and higher) than that.
        mock_record.return_value = (MagicMock(risk_score=95), True, False)

        results = process_brand_generated(MagicMock(), make_brand())

        assert results[0].risk_score == 95
        assert results[0].risk_bucket == "high"

    @patch("worker.pipeline._record_finding")
    @patch("worker.pipeline.has_mx_records", return_value=False)
    @patch(
        "worker.pipeline.check_registration",
        return_value=RegistrationStatus(status="registered"),
    )
    @patch("worker.pipeline.load_tld_nameservers", return_value=[("ns1.", "1.2.3.4")])
    @patch("worker.pipeline.load_tld_whois_host", return_value=None)
    @patch("worker.pipeline.generate_variants")
    def test_re_seen_finding_with_no_incidents_is_not_reported_as_new(
        self, mock_gen, mock_whois, mock_ns, mock_check, mock_mx, mock_record
    ):
        mock_gen.return_value = [Candidate("acme-login.com", "dictionary")]
        mock_record.return_value = (MagicMock(), False, False)  # already existed, nothing changed

        results = process_brand_generated(MagicMock(), make_brand())

        assert results == []
        mock_record.assert_called_once()

    @patch("worker.pipeline._record_finding")
    @patch("worker.pipeline.has_mx_records", return_value=False)
    @patch(
        "worker.pipeline.check_registration",
        return_value=RegistrationStatus(status="registered"),
    )
    @patch("worker.pipeline.load_tld_nameservers", return_value=[("ns1.", "1.2.3.4")])
    @patch("worker.pipeline.load_tld_whois_host", return_value=None)
    @patch("worker.pipeline.generate_variants")
    def test_re_seen_finding_with_a_new_incident_is_notable(
        self, mock_gen, mock_whois, mock_ns, mock_check, mock_mx, mock_record
    ):
        """A known finding that just grew a login form is exactly the
        kind of thing a digest should surface, even though the row
        itself isn't new."""
        mock_gen.return_value = [Candidate("acme-login.com", "dictionary")]
        # not new, but had an incident
        mock_record.return_value = (MagicMock(risk_score=50), False, True)

        results = process_brand_generated(MagicMock(), make_brand())

        assert len(results) == 1
        assert results[0].domain == "acme-login.com"

    @patch("worker.pipeline._record_finding")
    @patch("worker.pipeline.has_mx_records", return_value=False)
    @patch(
        "worker.pipeline.check_registration",
        return_value=RegistrationStatus(status="registered"),
    )
    @patch("worker.pipeline.load_tld_nameservers", return_value=[("ns1.", "1.2.3.4")])
    @patch("worker.pipeline.load_tld_whois_host", return_value=None)
    @patch("worker.pipeline.generate_variants")
    def test_owned_domains_seed_additional_candidates(
        self, mock_gen, mock_whois, mock_ns, mock_check, mock_mx, mock_record
    ):
        """A squat of an owned secondary domain is worth catching too,
        not just a squat of the primary brand name."""
        mock_gen.side_effect = [
            [Candidate("acme-login.com", "dictionary")],  # seeded from brand.name
            [Candidate("acme-shpo.net", "transposition")],  # seeded from acme-shop.com
        ]
        mock_record.return_value = (MagicMock(risk_score=50), True, False)

        results = process_brand_generated(
            MagicMock(), make_brand(owned_domains=["acme-shop.com"])
        )

        assert mock_gen.call_count == 2
        first_call_name = mock_gen.call_args_list[0].args[0]
        second_call_name = mock_gen.call_args_list[1].args[0]
        assert first_call_name == "acme"
        assert second_call_name == "acme-shop"
        domains_recorded = {c.domain for c in results}
        assert domains_recorded == {"acme-login.com", "acme-shpo.net"}

    @patch("worker.pipeline._record_finding")
    @patch("worker.pipeline.check_registration")
    @patch("worker.pipeline.load_tld_nameservers", return_value=[("ns1.", "1.2.3.4")])
    @patch("worker.pipeline.load_tld_whois_host", return_value=None)
    @patch("worker.pipeline.generate_variants")
    def test_owned_domain_itself_is_never_checked_or_recorded(
        self, mock_gen, mock_whois, mock_ns, mock_check, mock_record
    ):
        """No point spending an RDAP/DNS check confirming what the
        tenant already told us they own — filtered out before the
        network-check loop, not after."""
        mock_gen.return_value = [
            Candidate("acme-shop.com", "*original-ish"),  # the owned domain itself, generated
            Candidate("acme-shpo.com", "transposition"),
        ]
        mock_check.return_value = RegistrationStatus(status="unregistered")

        process_brand_generated(MagicMock(), make_brand(owned_domains=["acme-shop.com"]))

        checked_domains = [c.args[0] for c in mock_check.call_args_list]
        assert "acme-shop.com" not in checked_domains
        assert "acme-shpo.com" in checked_domains

    @patch("worker.pipeline._record_finding")
    @patch("worker.pipeline.has_mx_records", return_value=False)
    @patch(
        "worker.pipeline.check_registration",
        return_value=RegistrationStatus(status="registered"),
    )
    @patch("worker.pipeline.load_tld_nameservers", return_value=[("ns1.", "1.2.3.4")])
    @patch("worker.pipeline.load_tld_whois_host", return_value=None)
    @patch("worker.pipeline.generate_variants")
    def test_risk_score_uses_the_closest_seed_name(
        self, mock_gen, mock_whois, mock_ns, mock_check, mock_mx, mock_record
    ):
        """A squat of 'acme-shop' scored only against 'acme' would
        understate how close a match it really is."""
        mock_gen.side_effect = [
            [],  # nothing from brand.name this time
            [Candidate("acme-shpo.com", "transposition")],  # from the owned domain
        ]
        mock_record.return_value = (MagicMock(risk_score=50), True, False)

        process_brand_generated(MagicMock(), make_brand(owned_domains=["acme-shop.com"]))

        _, kwargs = mock_record.call_args
        # levenshtein("acme-shop", "acme-shpo") == 2, vs. 5 against "acme" —
        # scoring against only brand.name would understate the risk.
        assert "edit_distance=2" in kwargs["risk_factors"]


class TestProcessBrandGeneratedResumeAndRateLimit:
    """The other half of resumability: a suspend/resume cycle across
    separate worker invocations must make real forward progress, not
    restart the (potentially huge — core/variants.py) candidate list
    from scratch every time."""

    @patch("worker.pipeline._record_finding")
    @patch("worker.pipeline.has_mx_records", return_value=False)
    @patch("worker.pipeline.check_registration")
    @patch("worker.pipeline.load_tld_nameservers", return_value=[("ns1.", "1.2.3.4")])
    @patch("worker.pipeline.load_tld_whois_host", return_value=None)
    @patch("worker.pipeline.generate_variants")
    def test_resumes_from_the_persisted_cursor(
        self, mock_gen, mock_whois, mock_ns, mock_check, mock_mx, mock_record
    ):
        mock_gen.return_value = [
            Candidate("acme-a.com", "insertion"),
            Candidate("acme-b.com", "insertion"),
            Candidate("acme-c.com", "insertion"),
        ]
        mock_check.return_value = RegistrationStatus(status="unregistered")

        process_brand_generated(MagicMock(), make_brand(generated_scan_cursor="acme-a.com"))

        checked = [c.args[0] for c in mock_check.call_args_list]
        assert checked == ["acme-b.com", "acme-c.com"]  # not re-checking acme-a.com

    @patch("worker.pipeline._record_finding")
    @patch("worker.pipeline.has_mx_records", return_value=False)
    @patch("worker.pipeline.check_registration")
    @patch("worker.pipeline.load_tld_nameservers", return_value=[("ns1.", "1.2.3.4")])
    @patch("worker.pipeline.load_tld_whois_host", return_value=None)
    @patch("worker.pipeline.generate_variants")
    def test_stale_cursor_falls_back_to_the_start(
        self, mock_gen, mock_whois, mock_ns, mock_check, mock_mx, mock_record
    ):
        """Brand config changed since the cursor was set — the cursor
        domain isn't in this run's list at all, so there's no
        meaningful resume point."""
        mock_gen.return_value = [Candidate("acme-a.com", "insertion")]
        mock_check.return_value = RegistrationStatus(status="unregistered")

        process_brand_generated(
            MagicMock(), make_brand(generated_scan_cursor="no-longer-generated.com")
        )

        checked = [c.args[0] for c in mock_check.call_args_list]
        assert checked == ["acme-a.com"]

    @patch("worker.pipeline._record_finding")
    @patch("worker.pipeline.has_mx_records", return_value=False)
    @patch("worker.pipeline.check_registration")
    @patch("worker.pipeline.load_tld_nameservers", return_value=[("ns1.", "1.2.3.4")])
    @patch("worker.pipeline.load_tld_whois_host", return_value=None)
    @patch("worker.pipeline.generate_variants")
    def test_full_pass_clears_the_cursor(
        self, mock_gen, mock_whois, mock_ns, mock_check, mock_mx, mock_record
    ):
        mock_gen.return_value = [
            Candidate("acme-a.com", "insertion"),
            Candidate("acme-b.com", "insertion"),
        ]
        mock_check.return_value = RegistrationStatus(status="unregistered")
        brand = make_brand(generated_scan_cursor="acme-a.com")  # a resumed, not fresh, run

        process_brand_generated(MagicMock(), brand)

        assert brand.generated_scan_cursor is None  # reached the end — ready for a fresh pass

    @patch("worker.pipeline._record_finding")
    @patch("worker.pipeline.has_mx_records", return_value=False)
    @patch("worker.pipeline.check_registration")
    @patch("worker.pipeline.load_tld_nameservers", return_value=[("ns1.", "1.2.3.4")])
    @patch("worker.pipeline.load_tld_whois_host", return_value=None)
    @patch("worker.pipeline.generate_variants")
    def test_rate_limit_stops_the_scan_and_sets_the_cursor_at_the_last_success(
        self, mock_gen, mock_whois, mock_ns, mock_check, mock_mx, mock_record
    ):
        mock_gen.return_value = [
            Candidate("acme-a.com", "insertion"),
            Candidate("acme-b.com", "insertion"),
            Candidate("acme-c.com", "insertion"),
        ]
        mock_check.side_effect = [
            RegistrationStatus(status="unregistered"),  # acme-a.com: fine
            RegistrationStatus(status="unknown", rate_limited=True, retry_after_seconds=30),
        ]
        rate_limiter = MagicMock(tripped=False)
        rate_limiter.is_active.return_value = False
        brand = make_brand()

        process_brand_generated(MagicMock(), brand, rate_limiter=rate_limiter)

        rate_limiter.trip.assert_called_once_with(30)
        assert brand.generated_scan_cursor == "acme-a.com"  # not the rate-limited candidate
        # acme-c.com never even attempted this run
        checked = [c.args[0] for c in mock_check.call_args_list]
        assert checked == ["acme-a.com", "acme-b.com"]

    @patch("worker.pipeline._generate_all_candidates")
    def test_active_rate_limit_skips_the_scan_entirely(self, mock_gen_all):
        rate_limiter = MagicMock()
        rate_limiter.is_active.return_value = True

        results = process_brand_generated(MagicMock(), make_brand(), rate_limiter=rate_limiter)

        assert results == []
        mock_gen_all.assert_not_called()  # doesn't even bother generating candidates

    def test_starts_the_clock_on_a_fresh_pass_that_does_not_finish(self):
        with (
            patch(
                "worker.pipeline.generate_variants",
                return_value=[Candidate("acme-a.com", "x"), Candidate("acme-b.com", "x")],
            ),
            patch(
                "worker.pipeline.check_registration",
                return_value=RegistrationStatus(status="unregistered"),
            ),
            patch("worker.pipeline.load_tld_nameservers", return_value=[("ns1.", "1.2.3.4")]),
            patch("worker.pipeline.load_tld_whois_host", return_value=None),
            patch("worker.pipeline._record_finding"),
        ):
            brand = make_brand()
            before = datetime.now(UTC)

            # Stop after the first candidate — pass doesn't complete,
            # so generated_scan_started_at should still be set (not
            # cleared the way a full pass would clear it).
            process_brand_generated(MagicMock(), brand, should_stop=lambda: True)

            assert brand.generated_scan_started_at is not None
            assert brand.generated_scan_started_at >= before

    @patch("worker.pipeline._record_finding")
    @patch("worker.pipeline.has_mx_records", return_value=False)
    @patch("worker.pipeline.check_registration")
    @patch("worker.pipeline.load_tld_nameservers", return_value=[("ns1.", "1.2.3.4")])
    @patch("worker.pipeline.load_tld_whois_host", return_value=None)
    @patch("worker.pipeline.generate_variants")
    def test_a_stale_cursor_is_discarded_and_the_pass_restarts(
        self, mock_gen, mock_whois, mock_ns, mock_check, mock_mx, mock_record
    ):
        """The gap this exists to close: a resumed pass that's been
        dragging on for over a day is running on progressively staler
        DNS/RDAP state for everything before the cursor — better to eat
        the cost of a fresh full pass than keep deferring it further."""
        mock_gen.return_value = [
            Candidate("acme-a.com", "insertion"),
            Candidate("acme-b.com", "insertion"),
        ]
        mock_check.return_value = RegistrationStatus(status="unregistered")
        stale_start = datetime.now(UTC) - timedelta(hours=25)
        brand = make_brand(
            generated_scan_cursor="acme-a.com", generated_scan_started_at=stale_start
        )

        process_brand_generated(MagicMock(), brand)

        checked = [c.args[0] for c in mock_check.call_args_list]
        assert checked == ["acme-a.com", "acme-b.com"]  # re-checked, not skipped

    @patch("worker.pipeline._record_finding")
    @patch("worker.pipeline.has_mx_records", return_value=False)
    @patch("worker.pipeline.check_registration")
    @patch("worker.pipeline.load_tld_nameservers", return_value=[("ns1.", "1.2.3.4")])
    @patch("worker.pipeline.load_tld_whois_host", return_value=None)
    @patch("worker.pipeline.generate_variants")
    def test_a_recent_cursor_is_not_discarded(
        self, mock_gen, mock_whois, mock_ns, mock_check, mock_mx, mock_record
    ):
        mock_gen.return_value = [
            Candidate("acme-a.com", "insertion"),
            Candidate("acme-b.com", "insertion"),
        ]
        mock_check.return_value = RegistrationStatus(status="unregistered")
        recent_start = datetime.now(UTC) - timedelta(hours=1)
        brand = make_brand(
            generated_scan_cursor="acme-a.com", generated_scan_started_at=recent_start
        )

        process_brand_generated(MagicMock(), brand)

        checked = [c.args[0] for c in mock_check.call_args_list]
        assert checked == ["acme-b.com"]  # resumed normally, acme-a.com not re-checked

    @patch("worker.pipeline._record_finding")
    @patch("worker.pipeline.has_mx_records", return_value=False)
    @patch(
        "worker.pipeline.check_registration",
        return_value=RegistrationStatus(status="unregistered"),
    )
    @patch("worker.pipeline.load_tld_nameservers", return_value=[("ns1.", "1.2.3.4")])
    @patch("worker.pipeline.load_tld_whois_host", return_value=None)
    @patch("worker.pipeline.generate_variants")
    def test_full_pass_clears_the_started_at_timestamp_too(
        self, mock_gen, mock_whois, mock_ns, mock_check, mock_mx, mock_record
    ):
        mock_gen.return_value = [Candidate("acme-a.com", "insertion")]
        brand = make_brand(
            generated_scan_cursor=None, generated_scan_started_at=datetime.now(UTC)
        )

        process_brand_generated(MagicMock(), brand)

        assert brand.generated_scan_started_at is None

    @patch("worker.pipeline._record_finding")
    @patch("worker.pipeline.has_mx_records", return_value=False)
    @patch(
        "worker.pipeline.check_registration",
        return_value=RegistrationStatus(status="unregistered"),
    )
    @patch("worker.pipeline.load_tld_nameservers", return_value=[("ns1.", "1.2.3.4")])
    @patch("worker.pipeline.load_tld_whois_host", return_value=None)
    @patch("worker.pipeline.generate_variants")
    def test_full_pass_stamps_last_scan_completed_at(
        self, mock_gen, mock_whois, mock_ns, mock_check, mock_mx, mock_record
    ):
        mock_gen.return_value = [Candidate("acme-a.com", "insertion")]
        brand = make_brand()
        before = datetime.now(UTC)

        process_brand_generated(MagicMock(), brand)

        assert brand.last_scan_completed_at is not None
        assert brand.last_scan_completed_at >= before

    @patch("worker.pipeline.check_registration")
    def test_interrupted_pass_does_not_stamp_last_scan_completed_at(self, mock_check):
        with (
            patch(
                "worker.pipeline.generate_variants",
                return_value=[Candidate("acme-a.com", "x"), Candidate("acme-b.com", "x")],
            ),
            patch("worker.pipeline.load_tld_nameservers", return_value=[("ns1.", "1.2.3.4")]),
            patch("worker.pipeline.load_tld_whois_host", return_value=None),
            patch("worker.pipeline._record_finding"),
        ):
            mock_check.return_value = RegistrationStatus(status="unregistered")
            brand = make_brand()

            process_brand_generated(MagicMock(), brand, should_stop=lambda: True)

            assert brand.last_scan_completed_at is None


class TestProcessBrandCt:
    """Orchestration only — see TestProcessBrandGenerated's docstring;
    same black-box treatment of `_record_finding` here."""

    @patch("worker.pipeline.update_ct_cursor")
    @patch("worker.pipeline._record_finding")
    @patch("worker.pipeline.has_mx_records", return_value=True)
    @patch("worker.pipeline.poll_ct_logs")
    def test_successful_poll_creates_findings_and_advances_cursor(
        self, mock_poll, mock_mx, mock_record, mock_cursor
    ):
        mock_poll.return_value = CTPollResult(
            success=True,
            hits=[CertHit(cert_id=42, common_name="acme-billing.com", issued_at=None)],
            max_cert_id=42,
        )
        mock_record.return_value = (MagicMock(risk_score=50), True, False)

        results = process_brand_ct(MagicMock(), make_brand())

        assert len(results) == 1
        assert results[0].domain == "acme-billing.com"
        assert results[0].risk_bucket in ("low", "medium", "high")
        mock_cursor.assert_called_once()

    @patch("worker.pipeline.update_ct_cursor")
    @patch("worker.pipeline.poll_ct_logs")
    def test_failed_poll_does_not_advance_cursor_or_raise(self, mock_poll, mock_cursor):
        mock_poll.return_value = CTPollResult(success=False, hits=[], max_cert_id=None)

        results = process_brand_ct(MagicMock(), make_brand())

        assert results == []
        mock_cursor.assert_not_called()

    @patch("worker.pipeline.poll_ct_logs", side_effect=RuntimeError("boom"))
    def test_poll_exception_does_not_raise(self, _mock_poll):
        results = process_brand_ct(MagicMock(), make_brand())
        assert results == []

    @patch("worker.pipeline.update_ct_cursor")
    @patch("worker.pipeline._record_finding")
    @patch("worker.pipeline.has_mx_records", return_value=False)
    @patch("worker.pipeline.poll_ct_logs")
    def test_wildcard_common_name_is_stripped(self, mock_poll, mock_mx, mock_record, mock_cursor):
        mock_poll.return_value = CTPollResult(
            success=True,
            hits=[CertHit(cert_id=1, common_name="*.acme-billing.com", issued_at=None)],
            max_cert_id=1,
        )
        mock_record.return_value = (MagicMock(risk_score=50), True, False)

        results = process_brand_ct(MagicMock(), make_brand())

        assert results[0].domain == "acme-billing.com"

    @patch("worker.pipeline.update_ct_cursor")
    @patch("worker.pipeline._record_finding")
    @patch("worker.pipeline.poll_ct_logs")
    def test_owned_domain_hit_is_not_recorded_but_still_advances_cursor(
        self, mock_poll, mock_record, mock_cursor
    ):
        mock_poll.return_value = CTPollResult(
            success=True,
            hits=[CertHit(cert_id=7, common_name="acme-shop.com", issued_at=None)],
            max_cert_id=7,
        )

        results = process_brand_ct(MagicMock(), make_brand(owned_domains=["acme-shop.com"]))

        assert results == []
        mock_record.assert_not_called()
        mock_cursor.assert_called_once_with(ANY, ANY, 7)

    @patch("worker.pipeline.update_ct_cursor")
    @patch("worker.pipeline.poll_ct_logs")
    def test_rate_limited_poll_trips_the_limiter_and_does_not_advance_cursor(
        self, mock_poll, mock_cursor
    ):
        mock_poll.return_value = CTPollResult(
            success=False, hits=[], max_cert_id=None, rate_limited=True, retry_after_seconds=45
        )
        rate_limiter = MagicMock(tripped=False)
        rate_limiter.is_active.return_value = False

        results = process_brand_ct(MagicMock(), make_brand(), rate_limiter=rate_limiter)

        assert results == []
        rate_limiter.trip.assert_called_once_with(45)
        mock_cursor.assert_not_called()

    @patch("worker.pipeline.poll_ct_logs")
    def test_active_rate_limit_skips_the_poll_entirely(self, mock_poll):
        rate_limiter = MagicMock()
        rate_limiter.is_active.return_value = True

        results = process_brand_ct(MagicMock(), make_brand(), rate_limiter=rate_limiter)

        assert results == []
        mock_poll.assert_not_called()


class TestProcessBrandCustom:
    """Orchestration only — see TestProcessBrandGenerated's docstring.
    The actual "when does a manual entry become notable" logic now lives
    entirely inside `_record_finding` (its "registered" event IS that
    notability signal), so these tests just check process_brand_custom
    correctly combines (is_new, had_incidents) with its own
    `status == "registered"` condition — real diff/transition coverage
    is in TestRecordFinding below."""

    @patch("worker.pipeline._record_finding")
    @patch("worker.pipeline.has_mx_records", return_value=False)
    @patch(
        "worker.pipeline.check_registration",
        return_value=RegistrationStatus(status="registered", registrar="GoDaddy"),
    )
    @patch("worker.pipeline.load_tld_nameservers", return_value=[("ns1.", "1.2.3.4")])
    @patch("worker.pipeline.load_tld_whois_host", return_value=None)
    def test_new_row_already_registered_is_notable(
        self, mock_whois, mock_ns, mock_check, mock_mx, mock_record
    ):
        # is_new + registered-event fired
        mock_record.return_value = (MagicMock(risk_score=50), True, True)
        brand = make_brand(custom_domains=["acme-secure-login.net"])

        results = process_brand_custom(MagicMock(), brand)

        assert len(results) == 1
        assert results[0].domain == "acme-secure-login.net"
        assert results[0].source == "manual"

    @patch("worker.pipeline._record_finding")
    @patch("worker.pipeline.load_tld_nameservers", return_value=[("ns1.", "1.2.3.4")])
    @patch("worker.pipeline.load_tld_whois_host", return_value=None)
    def test_new_row_still_unregistered_is_not_notable(self, mock_whois, mock_ns, mock_record):
        """The whole point of persisting unregistered custom entries is
        visible confirmation the watch is active — but "we started
        watching" isn't itself alert-worthy."""
        mock_record.return_value = (MagicMock(), True, False)  # is_new, but not registered

        with patch(
            "worker.pipeline.check_registration",
            return_value=RegistrationStatus(status="unregistered"),
        ):
            brand = make_brand(custom_domains=["not-yet-taken.net"])
            results = process_brand_custom(MagicMock(), brand)

        assert results == []
        _, kwargs = mock_record.call_args
        assert kwargs["status"] == "unregistered"

    @patch("worker.pipeline._record_finding")
    @patch("worker.pipeline.check_registration")
    def test_owned_domain_in_custom_list_is_skipped(self, mock_check, mock_record):
        """Defensive — the add_owned_domain endpoint keeps these lists
        mutually exclusive, but a domain in both via a direct DB edit
        shouldn't get flagged as a squat of itself."""
        brand = make_brand(
            custom_domains=["acme-shop.com"], owned_domains=["acme-shop.com"]
        )

        results = process_brand_custom(MagicMock(), brand)

        assert results == []
        mock_check.assert_not_called()
        mock_record.assert_not_called()

    @patch("worker.pipeline._record_finding")
    @patch("worker.pipeline.has_mx_records", return_value=True)
    @patch(
        "worker.pipeline.check_registration",
        return_value=RegistrationStatus(status="registered"),
    )
    @patch("worker.pipeline.load_tld_nameservers", return_value=[("ns1.", "1.2.3.4")])
    @patch("worker.pipeline.load_tld_whois_host", return_value=None)
    def test_existing_row_transitioning_to_registered_is_notable(
        self, mock_whois, mock_ns, mock_check, mock_mx, mock_record
    ):
        """The actual point of this feature: a watched domain that was
        unregistered yesterday and is registered today must notify."""
        # not new, but registered-event fired
        mock_record.return_value = (MagicMock(risk_score=50), False, True)

        brand = make_brand(custom_domains=["watched.net"])
        results = process_brand_custom(MagicMock(), brand)

        assert len(results) == 1
        assert results[0].domain == "watched.net"

    @patch("worker.pipeline._record_finding")
    @patch("worker.pipeline.has_mx_records", return_value=False)
    @patch(
        "worker.pipeline.check_registration",
        return_value=RegistrationStatus(status="registered"),
    )
    @patch("worker.pipeline.load_tld_nameservers", return_value=[("ns1.", "1.2.3.4")])
    @patch("worker.pipeline.load_tld_whois_host", return_value=None)
    def test_still_registered_no_incident_is_not_re_notable(
        self, mock_whois, mock_ns, mock_check, mock_mx, mock_record
    ):
        mock_record.return_value = (MagicMock(), False, False)

        brand = make_brand(custom_domains=["long-watched.net"])
        results = process_brand_custom(MagicMock(), brand)

        assert results == []
        mock_record.assert_called_once()  # still re-checked/refreshed, just not re-notified

    @patch("worker.pipeline.check_registration", return_value=RegistrationStatus(status="unknown"))
    @patch("worker.pipeline.load_tld_nameservers", return_value=[("ns1.", "1.2.3.4")])
    @patch("worker.pipeline.load_tld_whois_host", return_value=None)
    def test_unknown_status_is_skipped_not_persisted(self, mock_whois, mock_ns, mock_check):
        """A transient check failure shouldn't overwrite a real prior
        status with 'unknown' — try again next run instead."""
        brand = make_brand(custom_domains=["flaky-check.net"])

        with patch("worker.pipeline._record_finding") as mock_record:
            results = process_brand_custom(MagicMock(), brand)

        assert results == []
        mock_record.assert_not_called()

    def test_malformed_domain_is_skipped_not_an_exception(self):
        results = process_brand_custom(MagicMock(), make_brand(custom_domains=["not-a-domain"]))
        assert results == []

    @patch("worker.pipeline._record_finding")
    @patch("worker.pipeline.has_mx_records", return_value=False)
    @patch(
        "worker.pipeline.check_registration",
        return_value=RegistrationStatus(status="registered"),
    )
    @patch("worker.pipeline.load_tld_nameservers", return_value=[("ns1.", "1.2.3.4")])
    @patch("worker.pipeline.load_tld_whois_host", return_value=None)
    def test_stops_mid_scan_on_shutdown(
        self, mock_whois, mock_ns, mock_check, mock_mx, mock_record
    ):
        mock_record.return_value = (MagicMock(risk_score=50), True, True)
        brand = make_brand(custom_domains=["first.net", "second.net", "third.net"])

        seen = {"n": 0}

        def should_stop():
            seen["n"] += 1
            return seen["n"] > 1

        results = process_brand_custom(MagicMock(), brand, should_stop)

        assert len(results) == 1
        assert mock_record.call_count == 1

    @patch("worker.pipeline._record_finding")
    @patch("worker.pipeline.has_mx_records", return_value=False)
    @patch("worker.pipeline.check_registration")
    @patch("worker.pipeline.load_tld_nameservers", return_value=[("ns1.", "1.2.3.4")])
    @patch("worker.pipeline.load_tld_whois_host", return_value=None)
    def test_resumes_from_the_persisted_cursor(
        self, mock_whois, mock_ns, mock_check, mock_mx, mock_record
    ):
        mock_check.return_value = RegistrationStatus(status="unregistered")
        mock_record.return_value = (MagicMock(), True, False)
        brand = make_brand(
            custom_domains=["a.net", "b.net", "c.net"], custom_scan_cursor="a.net"
        )

        process_brand_custom(MagicMock(), brand)

        checked = [c.args[0] for c in mock_check.call_args_list]
        assert checked == ["b.net", "c.net"]

    @patch("worker.pipeline._record_finding")
    @patch("worker.pipeline.has_mx_records", return_value=False)
    @patch("worker.pipeline.check_registration")
    @patch("worker.pipeline.load_tld_nameservers", return_value=[("ns1.", "1.2.3.4")])
    @patch("worker.pipeline.load_tld_whois_host", return_value=None)
    def test_full_pass_clears_the_cursor(
        self, mock_whois, mock_ns, mock_check, mock_mx, mock_record
    ):
        mock_check.return_value = RegistrationStatus(status="unregistered")
        mock_record.return_value = (MagicMock(), True, False)
        brand = make_brand(custom_domains=["a.net", "b.net"], custom_scan_cursor="a.net")

        process_brand_custom(MagicMock(), brand)

        assert brand.custom_scan_cursor is None

    @patch("worker.pipeline._record_finding")
    @patch("worker.pipeline.has_mx_records", return_value=False)
    @patch("worker.pipeline.check_registration")
    @patch("worker.pipeline.load_tld_nameservers", return_value=[("ns1.", "1.2.3.4")])
    @patch("worker.pipeline.load_tld_whois_host", return_value=None)
    def test_rate_limit_stops_the_scan_and_sets_the_cursor_at_the_last_success(
        self, mock_whois, mock_ns, mock_check, mock_mx, mock_record
    ):
        mock_check.side_effect = [
            RegistrationStatus(status="unregistered"),
            RegistrationStatus(status="unknown", rate_limited=True, retry_after_seconds=15),
        ]
        mock_record.return_value = (MagicMock(), True, False)
        rate_limiter = MagicMock(tripped=False)
        rate_limiter.is_active.return_value = False
        brand = make_brand(custom_domains=["a.net", "b.net", "c.net"])

        process_brand_custom(MagicMock(), brand, rate_limiter=rate_limiter)

        rate_limiter.trip.assert_called_once_with(15)
        assert brand.custom_scan_cursor == "a.net"
        checked = [c.args[0] for c in mock_check.call_args_list]
        assert checked == ["a.net", "b.net"]

    @patch("worker.pipeline.check_registration")
    def test_active_rate_limit_skips_the_scan_entirely(self, mock_check):
        rate_limiter = MagicMock()
        rate_limiter.is_active.return_value = True

        results = process_brand_custom(
            MagicMock(), make_brand(custom_domains=["a.net"]), rate_limiter=rate_limiter
        )

        assert results == []
        mock_check.assert_not_called()

    @patch("worker.pipeline._record_finding")
    @patch("worker.pipeline.has_mx_records", return_value=False)
    @patch(
        "worker.pipeline.check_registration",
        return_value=RegistrationStatus(status="unregistered"),
    )
    @patch("worker.pipeline.load_tld_nameservers", return_value=[("ns1.", "1.2.3.4")])
    @patch("worker.pipeline.load_tld_whois_host", return_value=None)
    def test_a_stale_cursor_is_discarded_and_the_pass_restarts(
        self, mock_whois, mock_ns, mock_check, mock_mx, mock_record
    ):
        mock_record.return_value = (MagicMock(), True, False)
        stale_start = datetime.now(UTC) - timedelta(hours=25)
        brand = make_brand(
            custom_domains=["a.net", "b.net"],
            custom_scan_cursor="a.net",
            custom_scan_started_at=stale_start,
        )

        process_brand_custom(MagicMock(), brand)

        checked = [c.args[0] for c in mock_check.call_args_list]
        assert checked == ["a.net", "b.net"]  # re-checked, not skipped

    @patch("worker.pipeline._record_finding")
    @patch("worker.pipeline.has_mx_records", return_value=False)
    @patch(
        "worker.pipeline.check_registration",
        return_value=RegistrationStatus(status="unregistered"),
    )
    @patch("worker.pipeline.load_tld_nameservers", return_value=[("ns1.", "1.2.3.4")])
    @patch("worker.pipeline.load_tld_whois_host", return_value=None)
    def test_a_recent_cursor_is_not_discarded(
        self, mock_whois, mock_ns, mock_check, mock_mx, mock_record
    ):
        mock_record.return_value = (MagicMock(), True, False)
        recent_start = datetime.now(UTC) - timedelta(hours=1)
        brand = make_brand(
            custom_domains=["a.net", "b.net"],
            custom_scan_cursor="a.net",
            custom_scan_started_at=recent_start,
        )

        process_brand_custom(MagicMock(), brand)

        checked = [c.args[0] for c in mock_check.call_args_list]
        assert checked == ["b.net"]


class TestRunOnDemandScan:
    """The ad hoc counterpart to process_brand_custom's per-domain
    check — same underlying acquisition/recording (_record_finding),
    just for one caller-supplied domain outside the daily cron. See
    TestRecordFinding for the actual diff/event-detection coverage."""

    @patch("worker.pipeline._record_finding")
    @patch("worker.pipeline.has_mx_records", return_value=True)
    @patch(
        "worker.pipeline.check_registration",
        return_value=RegistrationStatus(
            status="registered", registrar="GoDaddy", abuse_email="abuse@registrar.test"
        ),
    )
    @patch("worker.pipeline.load_tld_nameservers", return_value=[("ns1.", "1.2.3.4")])
    @patch("worker.pipeline.load_tld_whois_host", return_value=None)
    def test_registered_domain_is_recorded_with_on_demand_source(
        self, _mock_whois, _mock_ns, _mock_check, _mock_mx, mock_record
    ):
        mock_record.return_value = (MagicMock(), True, True)
        brand = make_brand()
        session = MagicMock()

        result = run_on_demand_scan(session, brand, "acme-secure-login.net")

        assert result.status == "registered"
        _, kwargs = mock_record.call_args
        assert kwargs["source"] == "on_demand"
        assert kwargs["abuse_email"] == "abuse@registrar.test"
        assert kwargs["status"] == "registered"
        session.commit.assert_called()

    @patch("worker.pipeline._record_finding")
    @patch("worker.pipeline.load_tld_nameservers", return_value=[("ns1.", "1.2.3.4")])
    @patch("worker.pipeline.load_tld_whois_host", return_value=None)
    def test_unregistered_domain_is_still_recorded(self, _mock_whois, _mock_ns, mock_record):
        """Unlike the generated path, an on-demand lookup should record
        "checked, not registered" too — that's a real, useful answer to
        "i tell the domain, you give me the evidence", not nothing."""
        mock_record.return_value = (MagicMock(), True, False)
        with patch(
            "worker.pipeline.check_registration",
            return_value=RegistrationStatus(status="unregistered"),
        ):
            result = run_on_demand_scan(MagicMock(), make_brand(), "not-yet-taken.net")

        assert result.status == "unregistered"
        mock_record.assert_called_once()

    @patch("worker.pipeline._record_finding")
    @patch("worker.pipeline.check_registration", return_value=RegistrationStatus(status="unknown"))
    @patch("worker.pipeline.load_tld_nameservers", return_value=[])
    @patch("worker.pipeline.load_tld_whois_host", return_value=None)
    def test_unknown_status_is_not_recorded(self, _mock_whois, _mock_ns, _mock_check, mock_record):
        result = run_on_demand_scan(MagicMock(), make_brand(), "example.zzz")

        assert result.status == "unknown"
        mock_record.assert_not_called()

    @patch("worker.pipeline._record_finding")
    @patch(
        "worker.pipeline.check_registration",
        return_value=RegistrationStatus(
            status="unknown", rate_limited=True, retry_after_seconds=30
        ),
    )
    @patch("worker.pipeline.load_tld_nameservers", return_value=[])
    @patch("worker.pipeline.load_tld_whois_host", return_value=None)
    def test_rate_limited_response_trips_the_limiter_and_records_nothing(
        self, _mock_whois, _mock_ns, _mock_check, mock_record
    ):
        session = MagicMock()

        result = run_on_demand_scan(session, make_brand(), "example.com")

        assert result.rate_limited is True
        mock_record.assert_not_called()

    def test_active_rate_limit_short_circuits_before_any_lookup(self):
        """An ad hoc lookup doesn't get to bypass a suspension the
        daily worker is already honoring."""
        session = MagicMock()
        state = MagicMock()
        state.suspended_until = datetime.now(UTC) + timedelta(minutes=5)
        # Match RateLimiter.is_active()'s isinstance guard.
        from shared.models import RateLimitState

        real_state = RateLimitState(resource="rdap", suspended_until=state.suspended_until)
        session.get.return_value = real_state

        with patch("worker.pipeline.check_registration") as mock_check:
            result = run_on_demand_scan(session, make_brand(), "example.com")

        assert result.status == "unknown"
        assert result.rate_limited is True
        mock_check.assert_not_called()


def _prior_finding(status="registered", registrar=None, dns=None, website=None):
    finding = MagicMock()
    finding.status = status
    finding.registrar = registrar
    finding.dns_snapshot = (dns or DnsSnapshot()).to_dict()
    finding.website_snapshot = (website or WebsiteSnapshot()).to_dict()
    return finding


class TestRecordFinding:
    """The actual diff/event-detection logic behind every notability
    decision in the three process_brand_* paths. This is the part worth
    testing in real depth — it's genuinely subtle (see the module's own
    docstring on why a plain "is this a new row" check isn't enough once
    unregistered entries and incident history are both in play)."""

    def _call(
        self,
        session=None,
        status="registered",
        registrar="GoDaddy",
        dns_snapshot=DnsSnapshot(),
        website_snapshot=WebsiteSnapshot(reachable=False),
        upsert_return=None,
        blocklist_hits=None,
        risk_score=50,
        risk_factors=(),
    ):
        session = session or MagicMock()
        with (
            patch("worker.pipeline.get_dns_snapshot", return_value=dns_snapshot),
            patch("worker.pipeline.check_domain_blocklist", return_value=blocklist_hits or {}),
            patch("worker.pipeline.crawl_website", return_value=website_snapshot),
            # Fast-path result is a stand-in for a "browser render didn't
            # improve anything" outcome unless a test overrides this —
            # keeps every existing test's expectations about the fast
            # path's own snapshot fields unchanged.
            patch(
                "worker.pipeline.render_with_browser",
                return_value=WebsiteSnapshot(reachable=False),
            ),
            patch("worker.pipeline.crawl_site_graph", return_value=SiteGraph()),
            patch("worker.pipeline.sync_site_graph"),
            # Screenshot capture defaults to "nothing captured" so
            # existing tests' expectations are unaffected unless a test
            # overrides these explicitly.
            patch("worker.pipeline.capture_screenshot", return_value=None),
            patch("worker.pipeline.list_reference_images", return_value=[]),
            patch("worker.pipeline.upsert_finding") as mock_upsert,
            patch("worker.pipeline.create_finding_event") as mock_event,
        ):
            mock_upsert.return_value = upsert_return or (MagicMock(), True)
            result = _record_finding(
                session,
                make_brand(),
                "acme-login.com",
                source="generated",
                status=status,
                registrar=registrar,
                created_date=None,
                risk_score=risk_score,
                risk_factors=list(risk_factors),
            )
            return result, mock_upsert, mock_event

    def test_first_ever_registration_emits_registered_event(self):
        session = MagicMock()
        session.get.return_value = None  # never seen before

        (finding, is_new, had_incidents), mock_upsert, mock_event = self._call(session=session)

        assert had_incidents is True
        mock_event.assert_called_once()
        _, kwargs = mock_event.call_args
        assert kwargs["event_type"] == "registered"

    def test_first_ever_unregistered_entry_acquires_nothing(self):
        """No point crawling/resolving DNS for a domain that doesn't
        exist — status='unregistered' should skip acquisition entirely."""
        session = MagicMock()
        session.get.return_value = None

        with (
            patch("worker.pipeline.get_dns_snapshot") as mock_dns,
            patch("worker.pipeline.crawl_website") as mock_crawl,
            patch("worker.pipeline.upsert_finding", return_value=(MagicMock(), True)),
            patch("worker.pipeline.create_finding_event") as mock_event,
        ):
            _, is_new, had_incidents = _record_finding(
                session,
                make_brand(),
                "acme-login.com",
                source="generated",
                status="unregistered",
                registrar=None,
                created_date=None,
                risk_score=None,
                risk_factors=[],
            )

        mock_dns.assert_not_called()
        mock_crawl.assert_not_called()
        mock_event.assert_not_called()
        assert had_incidents is False

    def test_transition_from_unregistered_to_registered_emits_registered_event(self):
        session = MagicMock()
        session.get.return_value = _prior_finding(status="unregistered")

        (_, _, had_incidents), _, mock_event = self._call(session=session)

        assert had_incidents is True
        event_types = [c.kwargs["event_type"] for c in mock_event.call_args_list]
        assert "registered" in event_types

    def test_still_registered_no_changes_emits_nothing(self):
        session = MagicMock()
        session.get.return_value = _prior_finding(status="registered", registrar="GoDaddy")

        (_, _, had_incidents), _, mock_event = self._call(session=session, registrar="GoDaddy")

        assert had_incidents is False
        mock_event.assert_not_called()

    def test_whois_change_detected_when_registrar_differs(self):
        session = MagicMock()
        session.get.return_value = _prior_finding(status="registered", registrar="GoDaddy")

        (_, _, had_incidents), _, mock_event = self._call(session=session, registrar="NameCheap")

        assert had_incidents is True
        event_types = [c.kwargs["event_type"] for c in mock_event.call_args_list]
        assert event_types == ["whois_change"]
        details = mock_event.call_args_list[0].kwargs["details"]
        assert details == {"old": "GoDaddy", "new": "NameCheap"}

    def test_whois_change_not_double_counted_on_first_registration(self):
        """Transitioning into 'registered' already emits a 'registered'
        event — it shouldn't *also* fire whois_change just because
        there was no previous registrar to compare against."""
        session = MagicMock()
        session.get.return_value = None

        (_, _, _), _, mock_event = self._call(session=session, registrar="GoDaddy")

        event_types = [c.kwargs["event_type"] for c in mock_event.call_args_list]
        assert event_types == ["registered"]

    def test_dns_change_detected_with_prior_snapshot(self):
        session = MagicMock()
        old_dns = DnsSnapshot(a_records=("1.1.1.1",), mx_records=(), ns_records=("ns1.old",))
        session.get.return_value = _prior_finding(
            status="registered", registrar="GoDaddy", dns=old_dns
        )
        new_dns = DnsSnapshot(a_records=("2.2.2.2",), mx_records=(), ns_records=("ns1.old",))

        (_, _, had_incidents), _, mock_event = self._call(
            session=session, registrar="GoDaddy", dns_snapshot=new_dns
        )

        assert had_incidents is True
        dns_events = [
            c for c in mock_event.call_args_list if c.kwargs["event_type"] == "dns_change"
        ]
        assert len(dns_events) == 1
        assert dns_events[0].kwargs["details"] == {
            "a": {"old": ["1.1.1.1"], "new": ["2.2.2.2"]}
        }

    def test_dns_change_not_flagged_without_a_prior_snapshot(self):
        """First-ever DNS acquisition has nothing to diff against — must
        not be treated as 'everything changed'."""
        session = MagicMock()
        session.get.return_value = _prior_finding(status="registered", registrar="GoDaddy")
        new_dns = DnsSnapshot(a_records=("2.2.2.2",))

        (_, _, had_incidents), _, mock_event = self._call(
            session=session, registrar="GoDaddy", dns_snapshot=new_dns
        )

        assert had_incidents is False
        mock_event.assert_not_called()

    def test_blocklisted_ip_fires_event_and_boosts_score(self):
        session = MagicMock()
        session.get.return_value = None
        dns_snapshot = DnsSnapshot(a_records=("1.2.3.4",))

        (_, _, had_incidents), mock_upsert, mock_event = self._call(
            session=session,
            dns_snapshot=dns_snapshot,
            blocklist_hits={"1.2.3.4": ["127.0.0.4"]},
            risk_score=20,
            risk_factors=["mx_configured"],
        )

        assert had_incidents is True
        blocklist_events = [
            c for c in mock_event.call_args_list if c.kwargs["event_type"] == "ip_blocklisted"
        ]
        assert len(blocklist_events) == 1
        assert blocklist_events[0].kwargs["details"] == {"ips": {"1.2.3.4": ["127.0.0.4"]}}

        _, kwargs = mock_upsert.call_args
        assert kwargs["risk_score"] == 20 + BLOCKLIST_RISK_BONUS
        assert "ip_blocklisted" in kwargs["risk_factors"]
        assert kwargs["dns_snapshot"]["blocklist"] == {"1.2.3.4": ["127.0.0.4"]}

    def test_clean_ip_does_not_touch_score_or_factors(self):
        session = MagicMock()
        session.get.return_value = None

        (_, _, _had_incidents), mock_upsert, mock_event = self._call(
            session=session,
            dns_snapshot=DnsSnapshot(a_records=("1.2.3.4",)),
            blocklist_hits={},
            risk_score=20,
            risk_factors=["mx_configured"],
        )

        blocklist_events = [
            c for c in mock_event.call_args_list if c.kwargs["event_type"] == "ip_blocklisted"
        ]
        assert blocklist_events == []

        _, kwargs = mock_upsert.call_args
        assert kwargs["risk_score"] == 20
        assert kwargs["risk_factors"] == ["mx_configured"]
        assert "blocklist" not in kwargs["dns_snapshot"]

    def test_still_listed_ip_does_not_fire_a_second_event(self):
        """A continuing listing isn't a new incident — only a newly
        appearing one is, same "nothing changed" contract as
        dns_change."""
        session = MagicMock()
        previous = _prior_finding(status="registered", registrar="GoDaddy")
        previous.dns_snapshot = {**previous.dns_snapshot, "blocklist": {"1.2.3.4": ["127.0.0.4"]}}
        session.get.return_value = previous

        (_, _, had_incidents), mock_upsert, mock_event = self._call(
            session=session,
            registrar="GoDaddy",
            dns_snapshot=DnsSnapshot(a_records=("1.2.3.4",)),
            blocklist_hits={"1.2.3.4": ["127.0.0.4"]},
            risk_score=20,
        )

        assert had_incidents is False
        blocklist_events = [
            c for c in mock_event.call_args_list if c.kwargs["event_type"] == "ip_blocklisted"
        ]
        assert blocklist_events == []
        # Still enriched/scored even though it isn't a *new* incident —
        # this is about what the finding currently carries, not just
        # the timeline.
        _, kwargs = mock_upsert.call_args
        assert kwargs["risk_score"] == 20 + BLOCKLIST_RISK_BONUS
        assert kwargs["dns_snapshot"]["blocklist"] == {"1.2.3.4": ["127.0.0.4"]}

    def test_newly_added_ip_on_an_already_listed_domain_fires_event_for_the_new_one_only(self):
        session = MagicMock()
        previous = _prior_finding(status="registered", registrar="GoDaddy")
        previous.dns_snapshot = {**previous.dns_snapshot, "blocklist": {"1.2.3.4": ["127.0.0.4"]}}
        session.get.return_value = previous

        (_, _, _), _, mock_event = self._call(
            session=session,
            registrar="GoDaddy",
            dns_snapshot=DnsSnapshot(a_records=("1.2.3.4", "5.6.7.8")),
            blocklist_hits={"1.2.3.4": ["127.0.0.4"], "5.6.7.8": ["127.0.0.2"]},
        )

        blocklist_events = [
            c for c in mock_event.call_args_list if c.kwargs["event_type"] == "ip_blocklisted"
        ]
        assert len(blocklist_events) == 1
        assert blocklist_events[0].kwargs["details"] == {"ips": {"5.6.7.8": ["127.0.0.2"]}}

    def test_website_content_change_detected(self):
        session = MagicMock()
        old_site = WebsiteSnapshot(reachable=True, content_hash="hash-old")
        session.get.return_value = _prior_finding(
            status="registered", registrar="GoDaddy", website=old_site
        )
        new_site = WebsiteSnapshot(reachable=True, content_hash="hash-new")

        (_, _, had_incidents), _, mock_event = self._call(
            session=session, registrar="GoDaddy", website_snapshot=new_site
        )

        assert had_incidents is True
        event_types = [c.kwargs["event_type"] for c in mock_event.call_args_list]
        assert "website_change" in event_types

    def test_form_appearing_is_detected(self):
        session = MagicMock()
        old_site = WebsiteSnapshot(reachable=True, content_hash="h1", has_forms=False)
        session.get.return_value = _prior_finding(
            status="registered", registrar="GoDaddy", website=old_site
        )
        new_site = WebsiteSnapshot(
            reachable=True, content_hash="h1", has_forms=True, form_count=1, has_password_field=True
        )

        (_, _, had_incidents), _, mock_event = self._call(
            session=session, registrar="GoDaddy", website_snapshot=new_site
        )

        assert had_incidents is True
        form_events = [
            c for c in mock_event.call_args_list if c.kwargs["event_type"] == "form_detected"
        ]
        assert len(form_events) == 1
        assert form_events[0].kwargs["details"]["has_password_field"] is True

    def test_form_already_known_is_not_re_flagged(self):
        session = MagicMock()
        old_site = WebsiteSnapshot(reachable=True, content_hash="h1", has_forms=True, form_count=1)
        session.get.return_value = _prior_finding(
            status="registered", registrar="GoDaddy", website=old_site
        )
        # same content hash, still has a form — nothing new
        new_site = WebsiteSnapshot(reachable=True, content_hash="h1", has_forms=True, form_count=1)

        (_, _, had_incidents), _, mock_event = self._call(
            session=session, registrar="GoDaddy", website_snapshot=new_site
        )

        assert had_incidents is False
        mock_event.assert_not_called()

    def test_spa_detected_is_notable(self):
        session = MagicMock()
        old_site = WebsiteSnapshot(reachable=True, content_hash="h1", is_spa=False)
        session.get.return_value = _prior_finding(
            status="registered", registrar="GoDaddy", website=old_site
        )
        new_site = WebsiteSnapshot(
            reachable=True, content_hash="h1", is_spa=True, spa_signals=("root_mount:root",)
        )

        (_, _, had_incidents), _, mock_event = self._call(
            session=session, registrar="GoDaddy", website_snapshot=new_site
        )

        assert had_incidents is True
        spa_events = [
            c for c in mock_event.call_args_list if c.kwargs["event_type"] == "spa_detected"
        ]
        assert len(spa_events) == 1
        assert spa_events[0].kwargs["details"]["signals"] == ["root_mount:root"]

    def test_spa_already_known_is_not_re_flagged(self):
        session = MagicMock()
        old_site = WebsiteSnapshot(reachable=True, content_hash="h1", is_spa=True)
        session.get.return_value = _prior_finding(
            status="registered", registrar="GoDaddy", website=old_site
        )
        new_site = WebsiteSnapshot(reachable=True, content_hash="h1", is_spa=True)

        (_, _, had_incidents), _, mock_event = self._call(
            session=session, registrar="GoDaddy", website_snapshot=new_site
        )

        assert had_incidents is False
        mock_event.assert_not_called()

    def test_browser_render_used_when_spa_detected_and_reachable(self):
        """A reachable browser-rendered snapshot replaces the blank
        fast-path one entirely — its content fields, not the SPA
        shell's, drive form_detected/website_change diffing."""
        session = MagicMock()
        session.get.return_value = None
        fast_path = WebsiteSnapshot(
            reachable=True, content_hash="shell-hash", is_spa=True, spa_signals=("root_mount:root",)
        )
        rendered = WebsiteSnapshot(
            reachable=True,
            content_hash="real-hash",
            has_forms=True,
            form_count=1,
            has_password_field=True,
        )

        with (
            patch("worker.pipeline.get_dns_snapshot", return_value=DnsSnapshot()),
            patch("worker.pipeline.crawl_website", return_value=fast_path),
            patch("worker.pipeline.render_with_browser", return_value=rendered) as mock_render,
            patch("worker.pipeline.crawl_site_graph", return_value=SiteGraph()),
            patch("worker.pipeline.sync_site_graph"),
            patch("worker.pipeline.capture_screenshot", return_value=None),
            patch("worker.pipeline.list_reference_images", return_value=[]),
            patch(
                "worker.pipeline.upsert_finding", return_value=(MagicMock(), True)
            ) as mock_upsert,
            patch("worker.pipeline.create_finding_event") as mock_event,
        ):
            _record_finding(
                session,
                make_brand(),
                "acme-login.com",
                source="generated",
                status="registered",
                registrar="GoDaddy",
                created_date=None,
                risk_score=50,
                risk_factors=[],
            )

        mock_render.assert_called_once_with("acme-login.com")
        _, kwargs = mock_upsert.call_args
        assert kwargs["website_snapshot"]["content_hash"] == "real-hash"  # rendered, not shell
        form_events = [
            c for c in mock_event.call_args_list if c.kwargs["event_type"] == "form_detected"
        ]
        assert len(form_events) == 1  # only visible once real content is used

    def test_browser_render_not_used_when_not_spa(self):
        session = MagicMock()
        session.get.return_value = None
        fast_path = WebsiteSnapshot(reachable=True, content_hash="h1", is_spa=False)

        with (
            patch("worker.pipeline.get_dns_snapshot", return_value=DnsSnapshot()),
            patch("worker.pipeline.crawl_website", return_value=fast_path),
            patch("worker.pipeline.render_with_browser") as mock_render,
            patch("worker.pipeline.crawl_site_graph", return_value=SiteGraph()),
            patch("worker.pipeline.sync_site_graph"),
            patch("worker.pipeline.capture_screenshot", return_value=None),
            patch("worker.pipeline.list_reference_images", return_value=[]),
            patch("worker.pipeline.upsert_finding", return_value=(MagicMock(), True)),
            patch("worker.pipeline.create_finding_event"),
        ):
            _record_finding(
                session,
                make_brand(),
                "acme-login.com",
                source="generated",
                status="registered",
                registrar="GoDaddy",
                created_date=None,
                risk_score=50,
                risk_factors=[],
            )

        mock_render.assert_not_called()

    def test_unreachable_browser_render_keeps_the_fast_path_snapshot(self):
        session = MagicMock()
        session.get.return_value = None
        fast_path = WebsiteSnapshot(
            reachable=True, content_hash="shell-hash", is_spa=True, spa_signals=("root_mount:root",)
        )

        with (
            patch("worker.pipeline.get_dns_snapshot", return_value=DnsSnapshot()),
            patch("worker.pipeline.crawl_website", return_value=fast_path),
            patch(
                "worker.pipeline.render_with_browser", return_value=WebsiteSnapshot(reachable=False)
            ),
            patch("worker.pipeline.crawl_site_graph", return_value=SiteGraph()),
            patch("worker.pipeline.sync_site_graph"),
            patch("worker.pipeline.capture_screenshot", return_value=None),
            patch("worker.pipeline.list_reference_images", return_value=[]),
            patch(
                "worker.pipeline.upsert_finding", return_value=(MagicMock(), True)
            ) as mock_upsert,
            patch("worker.pipeline.create_finding_event"),
        ):
            _record_finding(
                session,
                make_brand(),
                "acme-login.com",
                source="generated",
                status="registered",
                registrar="GoDaddy",
                created_date=None,
                risk_score=50,
                risk_factors=[],
            )

        _, kwargs = mock_upsert.call_args
        assert kwargs["website_snapshot"]["content_hash"] == "shell-hash"

    def test_browser_render_exception_does_not_raise_or_block_upsert(self):
        session = MagicMock()
        session.get.return_value = None
        fast_path = WebsiteSnapshot(reachable=True, content_hash="shell-hash", is_spa=True)

        with (
            patch("worker.pipeline.get_dns_snapshot", return_value=DnsSnapshot()),
            patch("worker.pipeline.crawl_website", return_value=fast_path),
            patch("worker.pipeline.render_with_browser", side_effect=RuntimeError("boom")),
            patch("worker.pipeline.crawl_site_graph", return_value=SiteGraph()),
            patch("worker.pipeline.sync_site_graph"),
            patch("worker.pipeline.capture_screenshot", return_value=None),
            patch("worker.pipeline.list_reference_images", return_value=[]),
            patch(
                "worker.pipeline.upsert_finding", return_value=(MagicMock(), True)
            ) as mock_upsert,
            patch("worker.pipeline.create_finding_event"),
        ):
            _record_finding(
                session,
                make_brand(),
                "acme-login.com",
                source="generated",
                status="registered",
                registrar="GoDaddy",
                created_date=None,
                risk_score=50,
                risk_factors=[],
            )

        mock_upsert.assert_called_once()

    def test_redirect_detected(self):
        session = MagicMock()
        old_site = WebsiteSnapshot(reachable=True, content_hash="h1", redirect_target=None)
        session.get.return_value = _prior_finding(
            status="registered", registrar="GoDaddy", website=old_site
        )
        new_site = WebsiteSnapshot(
            reachable=True, content_hash="h1", redirect_target="https://evil.example/"
        )

        (_, _, had_incidents), _, mock_event = self._call(
            session=session, registrar="GoDaddy", website_snapshot=new_site
        )

        assert had_incidents is True
        redirect_events = [
            c for c in mock_event.call_args_list if c.kwargs["event_type"] == "redirect_detected"
        ]
        assert redirect_events[0].kwargs["details"] == {"target": "https://evil.example/"}

    def test_dns_acquisition_failure_does_not_raise_or_block_upsert(self):
        session = MagicMock()
        session.get.return_value = _prior_finding(status="registered", registrar="GoDaddy")

        with (
            patch("worker.pipeline.get_dns_snapshot", side_effect=RuntimeError("boom")),
            patch("worker.pipeline.crawl_website", return_value=WebsiteSnapshot()),
            patch("worker.pipeline.crawl_site_graph", return_value=SiteGraph()),
            patch("worker.pipeline.sync_site_graph"),
            patch("worker.pipeline.capture_screenshot", return_value=None),
            patch("worker.pipeline.list_reference_images", return_value=[]),
            patch(
                "worker.pipeline.upsert_finding", return_value=(MagicMock(), False)
            ) as mock_upsert,
            patch("worker.pipeline.create_finding_event"),
        ):
            _record_finding(
                session,
                make_brand(),
                "acme-login.com",
                source="generated",
                status="registered",
                registrar="GoDaddy",
                created_date=None,
                risk_score=50,
                risk_factors=[],
            )

        mock_upsert.assert_called_once()  # still persisted despite the DNS failure

    def test_crawl_failure_does_not_raise_or_block_upsert(self):
        session = MagicMock()
        session.get.return_value = _prior_finding(status="registered", registrar="GoDaddy")

        with (
            patch("worker.pipeline.get_dns_snapshot", return_value=DnsSnapshot()),
            patch("worker.pipeline.crawl_website", side_effect=RuntimeError("boom")),
            patch("worker.pipeline.crawl_site_graph", return_value=SiteGraph()),
            patch("worker.pipeline.sync_site_graph"),
            patch("worker.pipeline.capture_screenshot", return_value=None),
            patch("worker.pipeline.list_reference_images", return_value=[]),
            patch(
                "worker.pipeline.upsert_finding", return_value=(MagicMock(), False)
            ) as mock_upsert,
            patch("worker.pipeline.create_finding_event"),
        ):
            _record_finding(
                session,
                make_brand(),
                "acme-login.com",
                source="generated",
                status="registered",
                registrar="GoDaddy",
                created_date=None,
                risk_score=50,
                risk_factors=[],
            )

        mock_upsert.assert_called_once()

    def test_upsert_receives_acquired_snapshots(self):
        session = MagicMock()
        session.get.return_value = None
        dns = DnsSnapshot(a_records=("1.2.3.4",))
        site = WebsiteSnapshot(reachable=True, content_hash="abc")

        (_, _, _), mock_upsert, _ = self._call(
            session=session, dns_snapshot=dns, website_snapshot=site
        )

        _, kwargs = mock_upsert.call_args
        assert kwargs["dns_snapshot"] == dns.to_dict()
        assert kwargs["website_snapshot"] == site.to_dict()

    def test_site_graph_is_crawled_and_synced_for_registered_findings(self):
        from core.site_graph import LinkRecord, PageRecord

        session = MagicMock()
        session.get.return_value = None
        graph = SiteGraph(
            pages=(
                PageRecord(
                    url="https://acme-login.com/",
                    status_code=200,
                    content_hash="h1",
                    last_modified="Mon, 01 Jan 2026 00:00:00 GMT",
                    etag='"abc"',
                    title="Home",
                    has_forms=True,
                    form_count=1,
                    has_password_field=True,
                ),
            ),
            links=(
                LinkRecord(
                    from_url="https://acme-login.com/",
                    to_url="https://acme-login.com/about",
                    is_external=False,
                ),
            ),
        )

        with (
            patch("worker.pipeline.get_dns_snapshot", return_value=DnsSnapshot()),
            patch("worker.pipeline.crawl_website", return_value=WebsiteSnapshot()),
            patch("worker.pipeline.crawl_site_graph", return_value=graph) as mock_crawl_graph,
            patch("worker.pipeline.sync_site_graph") as mock_sync_graph,
            patch("worker.pipeline.capture_screenshot", return_value=None),
            patch("worker.pipeline.list_reference_images", return_value=[]),
            patch("worker.pipeline.upsert_finding", return_value=(MagicMock(), True)),
            patch("worker.pipeline.create_finding_event"),
        ):
            _record_finding(
                session,
                make_brand(),
                "acme-login.com",
                source="generated",
                status="registered",
                registrar="GoDaddy",
                created_date=None,
                risk_score=50,
                risk_factors=[],
            )

        mock_crawl_graph.assert_called_once_with("acme-login.com")
        _, kwargs = mock_sync_graph.call_args
        assert kwargs["domain"] == "acme-login.com"
        assert kwargs["pages"] == [
            {
                "url": "https://acme-login.com/",
                "status_code": 200,
                "content_hash": "h1",
                "last_modified": "Mon, 01 Jan 2026 00:00:00 GMT",
                "etag": '"abc"',
                "title": "Home",
                "has_forms": True,
                "form_count": 1,
                "has_password_field": True,
                "is_spa": False,
                "spa_signals": (),
            }
        ]
        assert kwargs["links"] == [
            {
                "from_url": "https://acme-login.com/",
                "to_url": "https://acme-login.com/about",
                "is_external": False,
            }
        ]

    def test_site_graph_crawl_failure_does_not_raise_or_block_upsert(self):
        session = MagicMock()
        session.get.return_value = None

        with (
            patch("worker.pipeline.get_dns_snapshot", return_value=DnsSnapshot()),
            patch("worker.pipeline.crawl_website", return_value=WebsiteSnapshot()),
            patch("worker.pipeline.crawl_site_graph", side_effect=RuntimeError("boom")),
            patch("worker.pipeline.sync_site_graph") as mock_sync_graph,
            patch("worker.pipeline.capture_screenshot", return_value=None),
            patch("worker.pipeline.list_reference_images", return_value=[]),
            patch(
                "worker.pipeline.upsert_finding", return_value=(MagicMock(), True)
            ) as mock_upsert,
            patch("worker.pipeline.create_finding_event"),
        ):
            _record_finding(
                session,
                make_brand(),
                "acme-login.com",
                source="generated",
                status="registered",
                registrar="GoDaddy",
                created_date=None,
                risk_score=50,
                risk_factors=[],
            )

        mock_upsert.assert_called_once()
        mock_sync_graph.assert_not_called()

    def test_site_graph_is_not_crawled_for_unregistered_findings(self):
        session = MagicMock()
        session.get.return_value = None

        with (
            patch("worker.pipeline.crawl_site_graph") as mock_crawl_graph,
            patch("worker.pipeline.sync_site_graph") as mock_sync_graph,
            patch("worker.pipeline.capture_screenshot", return_value=None),
            patch("worker.pipeline.list_reference_images", return_value=[]),
            patch("worker.pipeline.upsert_finding", return_value=(MagicMock(), True)),
            patch("worker.pipeline.create_finding_event"),
        ):
            _record_finding(
                session,
                make_brand(),
                "acme-login.com",
                source="generated",
                status="unregistered",
                registrar=None,
                created_date=None,
                risk_score=None,
                risk_factors=[],
            )

        mock_crawl_graph.assert_not_called()
        mock_sync_graph.assert_not_called()


class TestScreenshotCapture:
    """Capture is deliberately gated — first registration or a real
    content_hash change, not every scan — to keep Playwright launches
    bounded. See worker/pipeline.py's should_capture_screenshot."""

    def _call(self, session, website_snapshot, capture_return=None, reference_images=None):
        with (
            patch("worker.pipeline.get_dns_snapshot", return_value=DnsSnapshot()),
            patch("worker.pipeline.crawl_website", return_value=website_snapshot),
            patch(
                "worker.pipeline.render_with_browser", return_value=WebsiteSnapshot(reachable=False)
            ),
            patch("worker.pipeline.crawl_site_graph", return_value=SiteGraph()),
            patch("worker.pipeline.sync_site_graph"),
            patch(
                "worker.pipeline.capture_screenshot", return_value=capture_return
            ) as mock_capture,
            patch(
                "worker.pipeline.list_reference_images", return_value=reference_images or []
            ),
            patch(
                "worker.pipeline.upsert_finding", return_value=(MagicMock(), True)
            ) as mock_upsert,
            patch("worker.pipeline.create_finding_event") as mock_event,
        ):
            _record_finding(
                session,
                make_brand(),
                "acme-login.com",
                source="generated",
                status="registered",
                registrar="GoDaddy",
                created_date=None,
                risk_score=50,
                risk_factors=[],
            )
        return mock_capture, mock_upsert, mock_event

    def test_captured_on_first_registration(self):
        session = MagicMock()
        session.get.return_value = None  # never seen before
        site = WebsiteSnapshot(reachable=True, content_hash="h1")

        mock_capture, mock_upsert, _ = self._call(
            session, site, capture_return=b"png-bytes"
        )

        mock_capture.assert_called_once_with("acme-login.com")
        _, kwargs = mock_upsert.call_args
        assert kwargs["screenshot_data"] == b"png-bytes"
        assert kwargs["screenshot_content_type"] == "image/png"

    def test_captured_when_content_hash_changes(self):
        session = MagicMock()
        session.get.return_value = _prior_finding(
            status="registered",
            registrar="GoDaddy",
            website=WebsiteSnapshot(reachable=True, content_hash="old-hash"),
        )
        site = WebsiteSnapshot(reachable=True, content_hash="new-hash")

        mock_capture, _, _ = self._call(session, site, capture_return=b"png-bytes")

        mock_capture.assert_called_once()

    def test_not_captured_when_content_is_unchanged(self):
        session = MagicMock()
        session.get.return_value = _prior_finding(
            status="registered",
            registrar="GoDaddy",
            website=WebsiteSnapshot(reachable=True, content_hash="same-hash"),
        )
        site = WebsiteSnapshot(reachable=True, content_hash="same-hash")

        mock_capture, _, _ = self._call(session, site)

        mock_capture.assert_not_called()

    def test_not_captured_when_site_is_unreachable(self):
        session = MagicMock()
        session.get.return_value = None
        site = WebsiteSnapshot(reachable=False)

        mock_capture, _, _ = self._call(session, site)

        mock_capture.assert_not_called()

    def test_capture_failure_does_not_raise_or_block_upsert(self):
        session = MagicMock()
        session.get.return_value = None
        site = WebsiteSnapshot(reachable=True, content_hash="h1")

        with (
            patch("worker.pipeline.get_dns_snapshot", return_value=DnsSnapshot()),
            patch("worker.pipeline.crawl_website", return_value=site),
            patch(
                "worker.pipeline.render_with_browser", return_value=WebsiteSnapshot(reachable=False)
            ),
            patch("worker.pipeline.crawl_site_graph", return_value=SiteGraph()),
            patch("worker.pipeline.sync_site_graph"),
            patch("worker.pipeline.capture_screenshot", side_effect=RuntimeError("boom")),
            patch("worker.pipeline.list_reference_images", return_value=[]),
            patch(
                "worker.pipeline.upsert_finding", return_value=(MagicMock(), True)
            ) as mock_upsert,
            patch("worker.pipeline.create_finding_event"),
        ):
            _record_finding(
                session,
                make_brand(),
                "acme-login.com",
                source="generated",
                status="registered",
                registrar="GoDaddy",
                created_date=None,
                risk_score=50,
                risk_factors=[],
            )

        mock_upsert.assert_called_once()
        _, kwargs = mock_upsert.call_args
        assert kwargs["screenshot_data"] is None


class TestVisualSimilarityComparison:
    def _call(self, reference_images, comparison_patches):
        session = MagicMock()
        session.get.return_value = None
        site = WebsiteSnapshot(reachable=True, content_hash="h1")

        with ExitStack() as stack:
            stack.enter_context(
                patch("worker.pipeline.get_dns_snapshot", return_value=DnsSnapshot())
            )
            stack.enter_context(patch("worker.pipeline.crawl_website", return_value=site))
            stack.enter_context(
                patch(
                    "worker.pipeline.render_with_browser",
                    return_value=WebsiteSnapshot(reachable=False),
                )
            )
            stack.enter_context(
                patch("worker.pipeline.crawl_site_graph", return_value=SiteGraph())
            )
            stack.enter_context(patch("worker.pipeline.sync_site_graph"))
            stack.enter_context(
                patch("worker.pipeline.capture_screenshot", return_value=b"png-bytes")
            )
            stack.enter_context(
                patch("worker.pipeline.list_reference_images", return_value=reference_images)
            )
            stack.enter_context(
                patch("worker.pipeline.upsert_finding", return_value=(MagicMock(), True))
            )
            mock_event = stack.enter_context(patch("worker.pipeline.create_finding_event"))
            for p in comparison_patches:
                stack.enter_context(p)

            _record_finding(
                session,
                make_brand(),
                "acme-login.com",
                source="generated",
                status="registered",
                registrar="GoDaddy",
                created_date=None,
                risk_score=50,
                risk_factors=[],
            )
        return mock_event

    def test_logo_match_emits_an_incident(self):
        from core.visual_similarity import SimilarityResult

        ref = MagicMock(id="ref-1", kind="logo", filename="logo.png")
        match = SimilarityResult(is_match=True, score=20.0, detail="good_matches=20")

        mock_event = self._call(
            [ref], [patch("worker.pipeline.find_logo_in_screenshot", return_value=match)]
        )

        logo_events = [
            c for c in mock_event.call_args_list if c.kwargs["event_type"] == "logo_match_detected"
        ]
        assert len(logo_events) == 1
        assert logo_events[0].kwargs["details"]["reference_filename"] == "logo.png"

    def test_site_clone_match_emits_an_incident(self):
        from core.visual_similarity import SimilarityResult

        ref = MagicMock(id="ref-1", kind="site_screenshot", filename="login-page.png")
        match = SimilarityResult(is_match=True, score=0.95, detail="hamming_distance=3")

        mock_event = self._call(
            [ref], [patch("worker.pipeline.compare_page_similarity", return_value=match)]
        )

        clone_events = [
            c for c in mock_event.call_args_list if c.kwargs["event_type"] == "site_clone_detected"
        ]
        assert len(clone_events) == 1
        assert clone_events[0].kwargs["details"]["score"] == 0.95

    def test_no_match_emits_no_incident(self):
        from core.visual_similarity import SimilarityResult

        ref = MagicMock(id="ref-1", kind="logo", filename="logo.png")
        no_match = SimilarityResult(is_match=False, score=1.0, detail="good_matches=1")

        mock_event = self._call(
            [ref], [patch("worker.pipeline.find_logo_in_screenshot", return_value=no_match)]
        )

        logo_events = [
            c for c in mock_event.call_args_list if c.kwargs["event_type"] == "logo_match_detected"
        ]
        assert logo_events == []

    def test_comparison_failure_does_not_raise_or_block_upsert(self):
        session = MagicMock()
        session.get.return_value = None
        site = WebsiteSnapshot(reachable=True, content_hash="h1")
        ref = MagicMock(id="ref-1", kind="logo", filename="logo.png")

        with (
            patch("worker.pipeline.get_dns_snapshot", return_value=DnsSnapshot()),
            patch("worker.pipeline.crawl_website", return_value=site),
            patch(
                "worker.pipeline.render_with_browser", return_value=WebsiteSnapshot(reachable=False)
            ),
            patch("worker.pipeline.crawl_site_graph", return_value=SiteGraph()),
            patch("worker.pipeline.sync_site_graph"),
            patch("worker.pipeline.capture_screenshot", return_value=b"png-bytes"),
            patch("worker.pipeline.list_reference_images", return_value=[ref]),
            patch(
                "worker.pipeline.find_logo_in_screenshot", side_effect=RuntimeError("boom")
            ),
            patch(
                "worker.pipeline.upsert_finding", return_value=(MagicMock(), True)
            ) as mock_upsert,
            patch("worker.pipeline.create_finding_event"),
        ):
            _record_finding(
                session,
                make_brand(),
                "acme-login.com",
                source="generated",
                status="registered",
                registrar="GoDaddy",
                created_date=None,
                risk_score=50,
                risk_factors=[],
            )

        mock_upsert.assert_called_once()  # still persisted despite the comparison failure


class TestProcessTenant:
    @patch("worker.pipeline.process_brand_ct", return_value=[])
    @patch("worker.pipeline.process_brand_generated", return_value=[])
    def test_inactive_brands_are_skipped(self, mock_generated, mock_ct):
        tenant = MagicMock()
        tenant.brands = [make_brand(active=False)]

        process_tenant(MagicMock(), tenant)

        mock_generated.assert_not_called()
        mock_ct.assert_not_called()

    @patch("worker.pipeline.process_brand_ct")
    @patch("worker.pipeline.process_brand_generated")
    def test_both_paths_run_independently_even_if_one_finds_nothing(
        self, mock_generated, mock_ct
    ):
        from adapters.ports import FindingSummary

        mock_generated.return_value = []
        mock_ct.return_value = [FindingSummary("x.com", "acme", "ct", "registered", 10, "low")]
        tenant = MagicMock()
        tenant.brands = [make_brand()]

        results = process_tenant(MagicMock(), tenant)

        assert len(results) == 1
        mock_generated.assert_called_once()
        mock_ct.assert_called_once()

    @patch("worker.pipeline.process_brand_custom", return_value=[])
    @patch("worker.pipeline.process_brand_ct", return_value=[])
    @patch("worker.pipeline.process_brand_generated", return_value=[])
    def test_the_same_rate_limiter_instances_are_shared_across_brands(
        self, mock_generated, mock_ct, mock_custom
    ):
        """A rate limit hit while checking one brand's candidates would
        hit every other brand's too — so tripping it must suspend all
        of them for the rest of this run, not just the brand that
        happened to trip it. That only works if they all share one
        instance."""
        tenant = MagicMock()
        tenant.brands = [make_brand(brand_id="brand-1"), make_brand(brand_id="brand-2")]

        process_tenant(MagicMock(), tenant)

        generated_limiters = [c.args[3] for c in mock_generated.call_args_list]
        custom_limiters = [c.args[3] for c in mock_custom.call_args_list]
        ct_limiters = [c.args[3] for c in mock_ct.call_args_list]

        assert generated_limiters[0] is generated_limiters[1]  # same instance, both brands
        assert generated_limiters[0] is custom_limiters[0]  # generated and custom share "rdap"
        assert ct_limiters[0] is not generated_limiters[0]  # "ct" is a separate resource


class TestRunDailyPipeline:
    @patch("worker.pipeline.process_tenant")
    @patch("worker.pipeline.get_active_tenants")
    def test_sends_digest_only_when_new_findings_and_email_present(
        self, mock_get_tenants, mock_process
    ):
        from adapters.ports import FindingSummary

        tenant_with_email = MagicMock(contact_email="owner@acme.com", name="Acme")
        tenant_without_email = MagicMock(contact_email=None, name="NoEmail Co")
        mock_get_tenants.return_value = [tenant_with_email, tenant_without_email]
        mock_process.return_value = [FindingSummary("x.com", "acme", "ct", "registered", 10, "low")]

        notifier = MagicMock()
        summary = run_daily_pipeline(MagicMock(), {"email": notifier})

        assert summary["tenants_processed"] == 2
        assert summary["digests_sent"] == 1
        notifier.send_digest.assert_called_once()

    @patch("worker.pipeline.process_tenant")
    @patch("worker.pipeline.get_active_tenants")
    def test_summary_reports_which_resources_were_rate_limited(
        self, mock_get_tenants, mock_process
    ):
        """So an operator can tell 'we stopped early because of a rate
        limit' from the run summary log line alone."""

        def trip_rdap(session, tenant, should_stop, rdap_limiter, ct_limiter):
            rdap_limiter.trip(retry_after_seconds=60)
            return []

        mock_get_tenants.return_value = [MagicMock(contact_email=None)]
        mock_process.side_effect = trip_rdap

        summary = run_daily_pipeline(MagicMock(), {})

        assert summary["rate_limited_resources"] == ["rdap"]

    @patch("worker.pipeline.process_tenant", return_value=[])
    @patch("worker.pipeline.get_active_tenants", return_value=[MagicMock(contact_email=None)])
    def test_summary_reports_no_rate_limits_when_none_hit(self, mock_get_tenants, mock_process):
        summary = run_daily_pipeline(MagicMock(), {})

        assert summary["rate_limited_resources"] == []

    @patch("worker.pipeline.process_tenant")
    @patch("worker.pipeline.get_active_tenants")
    def test_one_tenant_failing_does_not_stop_the_others(self, mock_get_tenants, mock_process):
        good_tenant = MagicMock(contact_email=None)
        bad_tenant = MagicMock(contact_email=None)
        mock_get_tenants.return_value = [bad_tenant, good_tenant]
        mock_process.side_effect = [RuntimeError("boom"), []]

        session = MagicMock()
        summary = run_daily_pipeline(session, {})

        assert summary["tenants_processed"] == 1
        session.rollback.assert_called_once()

    @patch("worker.pipeline.process_tenant")
    @patch("worker.pipeline.get_active_tenants")
    def test_should_stop_true_upfront_processes_nothing(self, mock_get_tenants, mock_process):
        mock_get_tenants.return_value = [MagicMock(), MagicMock()]

        summary = run_daily_pipeline(MagicMock(), {}, should_stop=lambda: True)

        assert summary["tenants_processed"] == 0
        mock_process.assert_not_called()

    @patch("worker.pipeline.process_tenant")
    @patch("worker.pipeline.get_active_tenants")
    def test_stop_after_first_tenant_still_commits_that_tenants_work(
        self, mock_get_tenants, mock_process
    ):
        """Graceful shutdown must not discard work already completed —
        only skip tenants not yet started."""
        tenant_a = MagicMock(contact_email=None)
        tenant_b = MagicMock(contact_email=None)
        mock_get_tenants.return_value = [tenant_a, tenant_b]
        mock_process.return_value = []

        calls = {"n": 0}

        def should_stop():
            # False for tenant_a's should_stop() checks, True starting
            # from when run_daily_pipeline checks before tenant_b.
            calls["n"] += 1
            return calls["n"] > 1

        session = MagicMock()
        summary = run_daily_pipeline(session, {}, should_stop=should_stop)

        assert summary["tenants_processed"] == 1
        mock_process.assert_called_once()
        assert mock_process.call_args.args[:3] == (session, tenant_a, should_stop)
        session.commit.assert_called_once()


class TestGracefulShutdownPropagation:
    """should_stop threaded through every inner loop — verifies the
    mechanism itself, independent of run_daily_pipeline's tenant-level
    test above."""

    @patch("worker.pipeline._record_finding")
    @patch("worker.pipeline.has_mx_records", return_value=False)
    @patch(
        "worker.pipeline.check_registration",
        return_value=RegistrationStatus(status="registered"),
    )
    @patch("worker.pipeline.load_tld_nameservers", return_value=[("ns1.", "1.2.3.4")])
    @patch("worker.pipeline.load_tld_whois_host", return_value=None)
    @patch("worker.pipeline.generate_variants")
    def test_generated_path_stops_mid_scan_and_keeps_prior_results(
        self, mock_gen, mock_whois, mock_ns, mock_check, mock_mx, mock_record
    ):
        mock_gen.return_value = [
            Candidate("first.com", "dictionary"),
            Candidate("second.com", "dictionary"),
            Candidate("third.com", "dictionary"),
        ]
        mock_record.return_value = (MagicMock(risk_score=50), True, False)

        # Stop after the first candidate is processed.
        seen = {"n": 0}

        def should_stop():
            seen["n"] += 1
            return seen["n"] > 1

        results = process_brand_generated(MagicMock(), make_brand(), should_stop)

        assert len(results) == 1
        assert results[0].domain == "first.com"
        assert mock_record.call_count == 1  # second/third never reached

    def test_ct_path_skips_poll_entirely_when_stop_already_requested(self):
        """Tightened after a live shutdown test showed a shutdown request
        arriving between the generated and CT paths for the same brand
        still cost one full CT poll round-trip — this checks should_stop
        before even calling poll_ct_logs."""
        with patch("worker.pipeline.poll_ct_logs") as mock_poll:
            results = process_brand_ct(MagicMock(), make_brand(), should_stop=lambda: True)

        assert results == []
        mock_poll.assert_not_called()

    def test_ct_path_stops_before_any_hit_and_does_not_advance_cursor(self):
        brand = make_brand(ct_last_cert_id=10)

        with patch("worker.pipeline.poll_ct_logs") as mock_poll, patch(
            "worker.pipeline.update_ct_cursor"
        ) as mock_cursor:
            mock_poll.return_value = CTPollResult(
                success=True,
                hits=[CertHit(cert_id=99, common_name="acme-billing.com", issued_at=None)],
                max_cert_id=99,
            )

            results = process_brand_ct(MagicMock(), brand, should_stop=lambda: True)

            assert results == []
            mock_cursor.assert_not_called()  # cursor must not jump to 99 unprocessed

    def test_process_tenant_stops_before_remaining_brands(self):
        brand_a = make_brand(brand_id="a")
        brand_b = make_brand(brand_id="b")
        tenant = MagicMock()
        tenant.brands = [brand_a, brand_b]

        calls = {"n": 0}

        def should_stop():
            calls["n"] += 1
            return calls["n"] > 1  # allow brand_a's own check, stop before brand_b

        with patch("worker.pipeline.process_brand_generated", return_value=[]) as mock_gen, patch(
            "worker.pipeline.process_brand_ct", return_value=[]
        ) as mock_ct:
            process_tenant(MagicMock(), tenant, should_stop)

        # Only brand_a's should have been dispatched.
        assert mock_gen.call_count == 1
        assert mock_ct.call_count == 1


def make_tenant(**overrides):
    tenant = MagicMock()
    tenant.tenant_id = "tenant-1"
    tenant.name = "Acme"
    tenant.contact_email = None
    tenant.notification_channels = {}
    for key, value in overrides.items():
        setattr(tenant, key, value)
    return tenant


class TestDispatchNotifications:
    def test_fans_out_to_every_configured_channel(self):
        from adapters.ports import FindingSummary

        tenant = make_tenant(
            contact_email="owner@acme.com",
            notification_channels={"slack_webhook_url": "https://hooks.slack.example/abc"},
        )
        findings = [FindingSummary("x.com", "acme", "ct", "registered", 10, "low")]
        email_notifier = MagicMock()
        slack_notifier = MagicMock()
        discord_notifier = MagicMock()  # no destination configured -> should not fire

        sent = dispatch_notifications(
            tenant,
            findings,
            {"email": email_notifier, "slack": slack_notifier, "discord": discord_notifier},
        )

        assert sent == 2
        email_notifier.send_digest.assert_called_once_with("owner@acme.com", "Acme", findings)
        slack_notifier.send_digest.assert_called_once_with(
            "https://hooks.slack.example/abc", "Acme", findings
        )
        discord_notifier.send_digest.assert_not_called()

    def test_one_channel_failing_does_not_block_another(self):
        from adapters.ports import FindingSummary

        tenant = make_tenant(
            contact_email="owner@acme.com",
            notification_channels={"webhook_url": "https://example.com/hook"},
        )
        findings = [FindingSummary("x.com", "acme", "ct", "registered", 10, "low")]
        broken_email = MagicMock()
        broken_email.send_digest.side_effect = RuntimeError("SMTP down")
        working_webhook = MagicMock()

        sent = dispatch_notifications(
            tenant, findings, {"email": broken_email, "webhook": working_webhook}
        )

        assert sent == 1
        working_webhook.send_digest.assert_called_once()

    def test_no_channels_configured_sends_nothing(self):
        from adapters.ports import FindingSummary

        tenant = make_tenant()  # no contact_email, no notification_channels
        findings = [FindingSummary("x.com", "acme", "ct", "registered", 10, "low")]

        sent = dispatch_notifications(
            tenant, findings, {"email": MagicMock(), "slack": MagicMock()}
        )

        assert sent == 0

    def test_unknown_channel_key_is_ignored_not_an_error(self):
        from adapters.ports import FindingSummary

        tenant = make_tenant(contact_email="owner@acme.com")
        findings = [FindingSummary("x.com", "acme", "ct", "registered", 10, "low")]

        sent = dispatch_notifications(
            tenant, findings, {"email": MagicMock(), "carrier_pigeon": MagicMock()}
        )

        assert sent == 1
