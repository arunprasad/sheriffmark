import io
from datetime import date, datetime

from pypdf import PdfReader

from core.pdf_report import (
    FindingReportData,
    IncidentEntry,
    build_finding_report,
    describe_incident,
)


def _minimal_data(**overrides) -> FindingReportData:
    defaults = dict(
        domain="acme-secure-login.com",
        brand_name="Acme Corp",
        source="generated",
        status="registered",
        registrar="Example Registrar LLC",
        created_date=date(2020, 1, 15),
        abuse_email="abuse@example-registrar.test",
        risk_score=75,
        risk_factors=["edit_distance<=1", "mx_configured"],
        resolution_status="open",
        resolution_note=None,
        first_seen=datetime(2026, 8, 20, 10, 0),
        last_checked=datetime(2026, 8, 29, 15, 0),
    )
    defaults.update(overrides)
    return FindingReportData(**defaults)


def _text(pdf_bytes: bytes) -> str:
    reader = PdfReader(io.BytesIO(pdf_bytes))
    return "\n".join(page.extract_text() for page in reader.pages)


class TestBuildFindingReport:
    def test_produces_a_real_pdf(self):
        pdf_bytes = build_finding_report(_minimal_data())
        assert pdf_bytes[:4] == b"%PDF"
        assert len(pdf_bytes) > 500

    def test_includes_core_registration_fields(self):
        text = _text(build_finding_report(_minimal_data()))
        assert "acme-secure-login.com" in text
        assert "Acme Corp" in text
        assert "Example Registrar LLC" in text
        assert "abuse@example-registrar.test" in text
        assert "2020-01-15" in text

    def test_missing_optional_fields_render_as_unknown_not_blank(self):
        data = _minimal_data(registrar=None, created_date=None, abuse_email=None)
        text = _text(build_finding_report(data))
        assert "Unknown" in text

    def test_no_screenshot_says_so_rather_than_erroring(self):
        text = _text(build_finding_report(_minimal_data(screenshot_data=None)))
        assert "No screenshot captured yet." in text

    def test_embeds_a_real_screenshot(self):
        # A minimal valid PNG (1x1 transparent pixel).
        png = bytes.fromhex(
            "89504e470d0a1a0a0000000d49484452000000010000000108"
            "0600000031e91d140000000a49444154789c6300010000050001"
            "0d0a2db40000000049454e44ae426082"
        )
        pdf_bytes = build_finding_report(_minimal_data(screenshot_data=png))
        assert pdf_bytes[:4] == b"%PDF"
        text = _text(pdf_bytes)
        assert "No screenshot captured yet." not in text

    def test_blocklist_hits_are_shown_in_dns_section(self):
        data = _minimal_data(
            dns_snapshot={
                "a": ["203.0.113.5"],
                "mx": [],
                "ns": [],
                "blocklist": {
                    "203.0.113.5": {"barracuda": ["127.0.0.2"], "spamcop": ["127.0.0.2"]}
                },
            }
        )
        text = _text(build_finding_report(data))
        assert "203.0.113.5" in text
        assert "barracuda" in text
        assert "spamcop" in text

    def test_no_dns_data_does_not_crash(self):
        text = _text(build_finding_report(_minimal_data(dns_snapshot={})))
        assert "None" in text  # A/MX/NS all render as "None", not blank

    def test_no_website_data_says_so(self):
        text = _text(build_finding_report(_minimal_data(website_snapshot={})))
        assert "No website data acquired yet." in text

    def test_incidents_render_and_sort_newest_first(self):
        data = _minimal_data(
            incidents=[
                IncidentEntry(
                    event_type="registered",
                    detected_at=datetime(2026, 8, 20, 10, 0),
                    description="Registrar: Example Registrar LLC",
                ),
                IncidentEntry(
                    event_type="ip_blocklisted",
                    detected_at=datetime(2026, 8, 29, 9, 0),
                    description="Listed: 203.0.113.5 (barracuda)",
                ),
            ]
        )
        text = _text(build_finding_report(data))
        # Newest (ip_blocklisted) should appear before the oldest
        # (registered) within the incident timeline section — "registered"
        # also appears earlier, as the finding's own Status value.
        timeline = text[text.index("Incident timeline") :]
        assert timeline.index("ip blocklisted") < timeline.index("registered")

    def test_no_incidents_says_so(self):
        text = _text(build_finding_report(_minimal_data(incidents=[])))
        assert "No incidents recorded yet." in text

    def test_resolution_note_rendered_when_present(self):
        data = _minimal_data(resolution_status="resolved", resolution_note="Took the site down.")
        text = _text(build_finding_report(data))
        assert "Took the site down." in text

    def test_generator_disclaimer_present(self):
        text = _text(build_finding_report(_minimal_data()))
        assert "Not" in text and "legal advice" in text


class TestDescribeIncident:
    def test_registered_with_registrar(self):
        assert describe_incident("registered", {"registrar": "GoDaddy"}) == "Registrar: GoDaddy"

    def test_registered_without_registrar(self):
        assert describe_incident("registered", {}) == "Registration detected, registrar unknown"

    def test_whois_change(self):
        assert describe_incident("whois_change", {"old": "A", "new": "B"}) == "A → B"

    def test_dns_change(self):
        result = describe_incident(
            "dns_change", {"a": {"old": ["1.1.1.1"], "new": ["2.2.2.2"]}}
        )
        assert result == "A: 1.1.1.1 → 2.2.2.2"

    def test_ip_blocklisted_with_hits(self):
        result = describe_incident(
            "ip_blocklisted", {"ips": {"1.2.3.4": {"barracuda": ["127.0.0.2"]}}}
        )
        assert result == "Listed: 1.2.3.4 (barracuda)"

    def test_ip_blocklisted_without_details(self):
        assert describe_incident("ip_blocklisted", {}) == "IP flagged on a public blocklist"

    def test_form_detected(self):
        result = describe_incident("form_detected", {"form_count": 2, "has_password_field": True})
        assert result == "2 form(s), including a password field"

    def test_resolution_note_preferred_over_label(self):
        assert describe_incident("resolved", {"note": "took it down"}) == "took it down"

    def test_resolution_without_note_falls_back_to_label(self):
        assert describe_incident("resolved_owned", {}) == "Resolved owned"

    def test_unknown_event_type_does_not_crash(self):
        assert describe_incident("something_new", {"a": 1}) == "{'a': 1}"
