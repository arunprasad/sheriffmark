from datetime import date
from unittest.mock import MagicMock, patch

import dns.rcode

from core.registration import (
    RegistrationStatus,
    _extract_abuse_email,
    _extract_created_date,
    _extract_registrar,
    _extract_whois_abuse_email,
    _extract_whois_created_date,
    _extract_whois_registrar,
    check_registration,
    load_tld_whois_host,
    rdap_lookup,
    whois_lookup,
)


class TestRdapLookup:
    def test_404_means_unregistered(self):
        session = MagicMock()
        session.get.return_value = MagicMock(status_code=404, json=lambda: {})

        result = rdap_lookup("nope.example", session=session)

        assert result == RegistrationStatus(status="unregistered")

    def test_404_with_empty_body_means_unregistered(self):
        """A registry with real RDAP saying "not found" (e.g. Verisign
        for .net) returns 404 with an empty body — .json() itself
        raises, not just returns an empty dict."""
        session = MagicMock()

        def _raise():
            raise ValueError("No JSON object could be decoded")

        session.get.return_value = MagicMock(status_code=404, json=_raise)

        result = rdap_lookup("nope.example", session=session)

        assert result == RegistrationStatus(status="unregistered")

    def test_404_with_no_rdap_service_title_means_unknown_not_unregistered(self):
        """rdap.org's *own* bootstrap-layer 404 (no RDAP route known
        for this TLD at all — confirmed live for .de and, surprisingly,
        .io) is a completely different signal from a registry saying
        the domain itself isn't registered. Collapsing them would both
        misreport status and silently suppress the whois fallback."""
        session = MagicMock()
        session.get.return_value = MagicMock(
            status_code=404,
            json=lambda: {
                "errorCode": 404,
                "title": "No RDAP service is available for this resource",
            },
        )

        result = rdap_lookup("nope.de", session=session)

        assert result == RegistrationStatus(status="unknown")

    def test_404_with_real_registry_error_body_means_unregistered(self):
        """A registry's own structured not-found error (e.g. .org's,
        which nests a "Terms of Service" title inside `notices`, not a
        top-level `title`) must not be mistaken for rdap.org's
        bootstrap-failure shape just because the body is non-empty."""
        session = MagicMock()
        session.get.return_value = MagicMock(
            status_code=404,
            json=lambda: {
                "rdapConformance": ["rdap_level_0"],
                "notices": [{"title": "Terms of Service", "description": ["..."]}],
            },
        )

        result = rdap_lookup("nope.org", session=session)

        assert result == RegistrationStatus(status="unregistered")

    def test_200_means_registered_with_parsed_details(self):
        session = MagicMock()
        session.get.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                "entities": [
                    {
                        "roles": ["registrar"],
                        "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar Inc."]]],
                        "entities": [
                            {
                                "roles": ["abuse"],
                                "vcardArray": [
                                    "vcard",
                                    [["email", {}, "text", "abuse@example-registrar.test"]],
                                ],
                            }
                        ],
                    }
                ],
                "events": [{"eventAction": "registration", "eventDate": "2020-01-15T00:00:00Z"}],
            },
        )

        result = rdap_lookup("taken.example", session=session)

        assert result.status == "registered"
        assert result.registrar == "Example Registrar Inc."
        assert result.created_date == date(2020, 1, 15)
        assert result.abuse_email == "abuse@example-registrar.test"

    def test_network_failure_is_unknown_not_an_exception(self):
        import requests

        session = MagicMock()
        session.get.side_effect = requests.ConnectionError("boom")

        result = rdap_lookup("flaky.example", session=session)

        assert result == RegistrationStatus(status="unknown")

    def test_unexpected_status_code_is_unknown(self):
        session = MagicMock()
        session.get.return_value = MagicMock(status_code=500)

        result = rdap_lookup("weird.example", session=session)

        assert result == RegistrationStatus(status="unknown")

    def test_429_is_distinguished_as_rate_limited(self):
        """Previously indistinguishable from any other non-200/404
        response — both collapsed into status="unknown", discarding
        the one signal that says *why* and *what to do about it*."""
        session = MagicMock()
        session.get.return_value = MagicMock(status_code=429, headers={"Retry-After": "30"})

        result = rdap_lookup("throttled.example", session=session)

        assert result.status == "unknown"
        assert result.rate_limited is True
        assert result.retry_after_seconds == 30.0

    def test_429_without_retry_after_header_still_flags_rate_limited(self):
        session = MagicMock()
        session.get.return_value = MagicMock(status_code=429, headers={})

        result = rdap_lookup("throttled.example", session=session)

        assert result.rate_limited is True
        assert result.retry_after_seconds is None


class TestExtractHelpers:
    def test_extract_registrar_returns_none_when_absent(self):
        assert _extract_registrar({"entities": []}) is None

    def test_extract_created_date_returns_none_on_bad_timestamp(self):
        data = {"events": [{"eventAction": "registration", "eventDate": "not-a-date"}]}
        assert _extract_created_date(data) is None

    def test_extract_abuse_email_returns_none_when_absent(self):
        assert _extract_abuse_email({"entities": []}) is None

    def test_extract_abuse_email_finds_nested_entity(self):
        """The standard ICANN RDAP shape — abuse is its own entity
        nested inside the registrar entity's own `entities` list."""
        data = {
            "entities": [
                {
                    "roles": ["registrar"],
                    "entities": [
                        {
                            "roles": ["abuse"],
                            "vcardArray": [
                                "vcard",
                                [["email", {}, "text", "abuse@registrar.test"]],
                            ],
                        }
                    ],
                }
            ]
        }
        assert _extract_abuse_email(data) == "abuse@registrar.test"

    def test_extract_abuse_email_finds_top_level_entity(self):
        """Some registries put the abuse contact at the top level
        instead of nesting it under the registrar entity."""
        data = {
            "entities": [
                {
                    "roles": ["abuse"],
                    "vcardArray": ["vcard", [["email", {}, "text", "abuse@registry.test"]]],
                }
            ]
        }
        assert _extract_abuse_email(data) == "abuse@registry.test"


class TestCheckRegistration:
    def test_no_ns_servers_is_unknown(self):
        result = check_registration("example.com", ns_servers=[])
        assert result == RegistrationStatus(status="unknown")

    @patch("core.registration.dns.query.udp")
    def test_nxdomain_falls_back_to_rdap(self, mock_udp):
        mock_resp = MagicMock()
        mock_resp.rcode.return_value = dns.rcode.NXDOMAIN
        mock_udp.return_value = mock_resp

        with patch("core.registration.rdap_lookup") as mock_rdap:
            mock_rdap.return_value = RegistrationStatus(status="unregistered")
            result = check_registration(
                "nope.example.com", ns_servers=[("ns1.example.", "1.2.3.4")]
            )

        mock_rdap.assert_called_once()
        assert result.status == "unregistered"

    @patch("core.registration.dns.query.udp")
    def test_ns_delegation_in_authority_means_registered(self, mock_udp):
        """DNS delegation alone confirms registration, but RDAP still
        gets called for enrichment (registrar/created_date/abuse_email)
        — this project needs more than a yes/no availability answer,
        unlike the legacy script this evolved from."""
        import dns.rdatatype

        mock_rrset = MagicMock()
        mock_rrset.rdtype = dns.rdatatype.NS
        mock_resp = MagicMock()
        mock_resp.rcode.return_value = dns.rcode.NOERROR
        mock_resp.authority = [mock_rrset]
        mock_udp.return_value = mock_resp

        with patch("core.registration.rdap_lookup") as mock_rdap:
            mock_rdap.return_value = RegistrationStatus(
                status="registered", registrar="GoDaddy", abuse_email="abuse@registrar.test"
            )
            result = check_registration(
                "taken.example.com", ns_servers=[("ns1.example.", "1.2.3.4")]
            )

        mock_rdap.assert_called_once()
        assert result.status == "registered"
        assert result.registrar == "GoDaddy"
        assert result.abuse_email == "abuse@registrar.test"

    @patch("core.registration.dns.query.udp")
    def test_ns_delegation_stands_even_if_rdap_disagrees_or_fails(self, mock_udp):
        """DNS delegation at the registry's own authoritative server is
        the more trustworthy signal here — RDAP is only being asked for
        extra detail, not a second opinion on whether it's registered
        at all. A flaky/wrong RDAP response shouldn't downgrade a
        DNS-confirmed registration."""
        import dns.rdatatype

        mock_rrset = MagicMock()
        mock_rrset.rdtype = dns.rdatatype.NS
        mock_resp = MagicMock()
        mock_resp.rcode.return_value = dns.rcode.NOERROR
        mock_resp.authority = [mock_rrset]
        mock_udp.return_value = mock_resp

        with patch(
            "core.registration.rdap_lookup", return_value=RegistrationStatus(status="unknown")
        ):
            result = check_registration(
                "taken.example.com", ns_servers=[("ns1.example.", "1.2.3.4")]
            )

        assert result.status == "registered"
        assert result.registrar is None

    @patch("core.registration.dns.query.udp")
    def test_ns_delegation_with_rdap_rate_limited_propagates_rate_limit(self, mock_udp):
        """A rate-limited enrichment attempt must not silently downgrade
        to "unknown" and get skipped — the caller treats `rate_limited`
        as "not actually checked, retry next run" regardless of
        `status`, so the DNS-confirmed finding isn't lost, just
        delayed."""
        import dns.rdatatype

        mock_rrset = MagicMock()
        mock_rrset.rdtype = dns.rdatatype.NS
        mock_resp = MagicMock()
        mock_resp.rcode.return_value = dns.rcode.NOERROR
        mock_resp.authority = [mock_rrset]
        mock_udp.return_value = mock_resp

        with patch(
            "core.registration.rdap_lookup",
            return_value=RegistrationStatus(
                status="unknown", rate_limited=True, retry_after_seconds=30
            ),
        ):
            result = check_registration(
                "taken.example.com", ns_servers=[("ns1.example.", "1.2.3.4")]
            )

        assert result.rate_limited is True
        assert result.retry_after_seconds == 30

    @patch("core.registration.dns.query.udp", side_effect=OSError("timeout"))
    def test_query_failure_is_unknown_not_an_exception(self, _mock_udp):
        result = check_registration("example.com", ns_servers=[("ns1.example.", "1.2.3.4")])
        assert result.status == "unknown"


class TestLoadTldWhoisHost:
    @patch("core.registration._whois_query")
    def test_parses_whois_line(self, mock_query):
        mock_query.return_value = (
            "% IANA WHOIS server\ndomain: EXAMPLE\nwhois:        whois.nic.example\n"
        )

        assert load_tld_whois_host("example") == "whois.nic.example"

    @patch("core.registration._whois_query")
    def test_no_whois_line_means_no_whois_support(self, mock_query):
        mock_query.return_value = "% IANA WHOIS server\ndomain: EXAMPLE\nstatus: ACTIVE\n"

        assert load_tld_whois_host("example") is None

    @patch("core.registration._whois_query", side_effect=OSError("timeout"))
    def test_connection_failure_is_none_not_an_exception(self, _mock_query):
        assert load_tld_whois_host("example") is None


class TestWhoisLookup:
    def test_no_known_host_is_unknown_without_a_connection_attempt(self):
        with patch("core.registration._whois_query") as mock_query:
            result = whois_lookup("nope.example", whois_host=None)

        mock_query.assert_not_called()
        assert result == RegistrationStatus(status="unknown")

    @patch("core.registration._whois_query", side_effect=OSError("connection refused"))
    def test_connection_failure_is_unknown(self, _mock_query):
        result = whois_lookup("nope.example", whois_host="whois.nic.example")
        assert result == RegistrationStatus(status="unknown")

    @patch("core.registration._whois_query", return_value="")
    def test_empty_response_is_unknown(self, _mock_query):
        result = whois_lookup("nope.example", whois_host="whois.nic.example")
        assert result == RegistrationStatus(status="unknown")

    @patch(
        "core.registration._whois_query",
        return_value="Domain: nope.example\nNo match for domain.\n",
    )
    def test_no_match_phrase_means_unregistered(self, _mock_query):
        result = whois_lookup("nope.example", whois_host="whois.nic.example")
        assert result == RegistrationStatus(status="unregistered")

    @patch(
        "core.registration._whois_query",
        return_value=(
            "Domain Name: TAKEN.EXAMPLE\n"
            "Registrar: Example Registrar Inc.\n"
            "Creation Date: 2019-03-04T00:00:00Z\n"
            "Registrar Abuse Contact Email: abuse@example-registrar.test\n"
        ),
    )
    def test_registered_with_parsed_details(self, _mock_query):
        result = whois_lookup("taken.example", whois_host="whois.nic.example")

        assert result.status == "registered"
        assert result.registrar == "Example Registrar Inc."
        assert result.created_date == date(2019, 3, 4)
        assert result.abuse_email == "abuse@example-registrar.test"

    @patch(
        "core.registration._whois_query",
        return_value="Domain Name: TAKEN.EXAMPLE\nStatus: active\n",
    )
    def test_registered_with_no_parseable_details_still_registered(self, _mock_query):
        """A registry whose field labels this heuristic doesn't
        recognize should never be misreported as unregistered — see
        the fail-safe direction documented on _WHOIS_NOT_FOUND_PHRASES."""
        result = whois_lookup("taken.example", whois_host="whois.nic.example")

        assert result.status == "registered"
        assert result.registrar is None
        assert result.created_date is None


class TestWhoisExtractHelpers:
    def test_extract_registrar_returns_none_when_absent(self):
        assert _extract_whois_registrar("Domain Name: EXAMPLE\n") is None

    def test_extract_created_date_handles_dd_mon_yyyy(self):
        assert _extract_whois_created_date("Creation Date: 04-Mar-2019\n") == date(2019, 3, 4)

    def test_extract_created_date_returns_none_on_unparseable_value(self):
        assert _extract_whois_created_date("Creation Date: sometime last year\n") is None

    def test_extract_abuse_email_returns_none_when_absent(self):
        assert _extract_whois_abuse_email("Domain Name: EXAMPLE\n") is None

    def test_extract_abuse_email_handles_icann_gtld_label(self):
        assert (
            _extract_whois_abuse_email("Registrar Abuse Contact Email: abuse@registrar.test\n")
            == "abuse@registrar.test"
        )

    def test_extract_abuse_email_handles_ripe_style_abuse_mailbox(self):
        assert (
            _extract_whois_abuse_email("abuse-mailbox: abuse@registry.test\n")
            == "abuse@registry.test"
        )


class TestCheckRegistrationWhoisFallback:
    @patch("core.registration.dns.query.udp")
    def test_rdap_unknown_falls_back_to_whois(self, mock_udp):
        mock_resp = MagicMock()
        mock_resp.rcode.return_value = dns.rcode.NXDOMAIN
        mock_udp.return_value = mock_resp

        with (
            patch(
                "core.registration.rdap_lookup",
                return_value=RegistrationStatus(status="unknown"),
            ),
            patch("core.registration.whois_lookup") as mock_whois,
        ):
            mock_whois.return_value = RegistrationStatus(status="registered")
            result = check_registration(
                "nope.example.cc",
                ns_servers=[("ns1.", "1.2.3.4")],
                whois_host="whois.nic.cc",
            )

        mock_whois.assert_called_once_with("nope.example.cc", "whois.nic.cc")
        assert result.status == "registered"

    @patch("core.registration.dns.query.udp")
    def test_rdap_rate_limited_does_not_fall_back_to_whois(self, mock_udp):
        """A 429 means "back off and retry RDAP later", not "RDAP
        doesn't exist here" — falling through to whois on a rate limit
        would mask the real signal RateLimiter needs to act on."""
        mock_resp = MagicMock()
        mock_resp.rcode.return_value = dns.rcode.NXDOMAIN
        mock_udp.return_value = mock_resp

        with (
            patch(
                "core.registration.rdap_lookup",
                return_value=RegistrationStatus(status="unknown", rate_limited=True),
            ),
            patch("core.registration.whois_lookup") as mock_whois,
        ):
            result = check_registration(
                "nope.example.cc", ns_servers=[("ns1.", "1.2.3.4")], whois_host="whois.nic.cc"
            )

        mock_whois.assert_not_called()
        assert result.rate_limited is True

    @patch("core.registration.dns.query.udp")
    def test_rdap_success_does_not_fall_back_to_whois(self, mock_udp):
        mock_resp = MagicMock()
        mock_resp.rcode.return_value = dns.rcode.NXDOMAIN
        mock_udp.return_value = mock_resp

        with (
            patch(
                "core.registration.rdap_lookup",
                return_value=RegistrationStatus(status="unregistered"),
            ),
            patch("core.registration.whois_lookup") as mock_whois,
        ):
            result = check_registration(
                "nope.example.cc", ns_servers=[("ns1.", "1.2.3.4")], whois_host="whois.nic.cc"
            )

        mock_whois.assert_not_called()
        assert result.status == "unregistered"


class TestHasMxRecords:
    @patch("core.registration.dns.resolver.resolve")
    def test_true_when_records_present(self, mock_resolve):
        from core.registration import has_mx_records

        mock_resolve.return_value = [MagicMock()]
        assert has_mx_records("example.com") is True

    @patch("core.registration.dns.resolver.resolve", side_effect=Exception("NXDOMAIN"))
    def test_false_on_any_failure(self, _mock_resolve):
        from core.registration import has_mx_records

        assert has_mx_records("nope.example.com") is False
