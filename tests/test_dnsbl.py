from unittest.mock import MagicMock, patch

import dns.resolver

from core.dnsbl import DNSBL_HOSTS, check_domain_blocklist, check_ip_blocklist


class TestCheckIpBlocklist:
    @patch("core.dnsbl.dns.resolver.resolve")
    def test_listed_ip_returns_return_codes(self, mock_resolve):
        mock_resolve.return_value = [MagicMock(__str__=lambda self: "127.0.0.2")]

        result = check_ip_blocklist("1.2.3.4", host="b.barracudacentral.org")

        assert result == ["127.0.0.2"]
        # Reversed-octet query against the list's own zone — the
        # standard DNSBL protocol convention.
        mock_resolve.assert_called_once_with(
            "4.3.2.1.b.barracudacentral.org", "A", lifetime=3.0
        )

    @patch("core.dnsbl.dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN())
    def test_not_listed_is_nxdomain(self, _mock_resolve):
        assert check_ip_blocklist("1.2.3.4", host="bl.spamcop.net") == []

    @patch("core.dnsbl.dns.resolver.resolve", side_effect=Exception("timeout"))
    def test_lookup_failure_fails_closed(self, _mock_resolve):
        assert check_ip_blocklist("1.2.3.4", host="bl.spamcop.net") == []

    def test_malformed_ip_returns_empty_without_a_lookup(self):
        with patch("core.dnsbl.dns.resolver.resolve") as mock_resolve:
            assert check_ip_blocklist("not-an-ip", host="bl.spamcop.net") == []
        mock_resolve.assert_not_called()

    def test_ipv6_returns_empty_without_a_lookup(self):
        """Both configured lists are IPv4-only zones."""
        with patch("core.dnsbl.dns.resolver.resolve") as mock_resolve:
            assert check_ip_blocklist("2001:db8::1", host="bl.spamcop.net") == []
        mock_resolve.assert_not_called()


class TestCheckDomainBlocklist:
    def test_returns_hits_only_for_listed_ips_grouped_by_list(self):
        def fake_check(ip, host, **_):
            if ip == "1.2.3.4" and host == DNSBL_HOSTS["barracuda"]:
                return ["127.0.0.2"]
            return []

        with patch("core.dnsbl.check_ip_blocklist", side_effect=fake_check):
            result = check_domain_blocklist(["1.2.3.4", "5.6.7.8"])

        assert result == {"1.2.3.4": {"barracuda": ["127.0.0.2"]}}

    def test_ip_listed_on_both_lists_records_both(self):
        with patch("core.dnsbl.check_ip_blocklist", return_value=["127.0.0.2"]):
            result = check_domain_blocklist(["1.2.3.4"])

        assert result == {
            "1.2.3.4": {"barracuda": ["127.0.0.2"], "spamcop": ["127.0.0.2"]}
        }

    @patch("core.dnsbl.check_ip_blocklist", return_value=[])
    def test_empty_when_nothing_listed(self, _mock_check):
        assert check_domain_blocklist(["1.2.3.4"]) == {}

    def test_empty_a_records_makes_no_lookup(self):
        with patch("core.dnsbl.check_ip_blocklist") as mock_check:
            assert check_domain_blocklist([]) == {}
        mock_check.assert_not_called()
