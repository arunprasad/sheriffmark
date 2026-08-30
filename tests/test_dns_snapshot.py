from unittest.mock import MagicMock, patch

from core.dns_snapshot import DnsSnapshot, get_dns_snapshot


class TestGetDnsSnapshot:
    @patch("core.dns_snapshot.dns.resolver.resolve")
    def test_resolves_each_record_type(self, mock_resolve):
        def side_effect(domain, record_type, lifetime):
            return {
                "A": [MagicMock(__str__=lambda self: "1.2.3.4")],
                "MX": [MagicMock(__str__=lambda self: "10 mail.acme.com.")],
                "NS": [MagicMock(__str__=lambda self: "ns1.acme.com.")],
            }[record_type]

        mock_resolve.side_effect = side_effect

        snap = get_dns_snapshot("acme.com")

        assert snap.a_records == ("1.2.3.4",)
        assert snap.mx_records == ("10 mail.acme.com",)  # trailing dot stripped
        assert snap.ns_records == ("ns1.acme.com",)

    @patch("core.dns_snapshot.dns.resolver.resolve", side_effect=Exception("NXDOMAIN"))
    def test_all_lookups_failing_returns_empty_snapshot_not_an_exception(self, _mock):
        snap = get_dns_snapshot("nowhere.example")
        assert snap == DnsSnapshot()

    def test_partial_failure_does_not_blank_out_successful_lookups(self):
        """Most domains have no MX record — that alone shouldn't wipe out
        A/NS records that did resolve."""

        def side_effect(domain, record_type, lifetime):
            if record_type == "MX":
                raise Exception("no MX record")
            return [MagicMock(__str__=lambda self: "1.2.3.4" if record_type == "A" else "ns1.x.")]

        with patch("core.dns_snapshot.dns.resolver.resolve", side_effect=side_effect):
            snap = get_dns_snapshot("acme.com")

        assert snap.a_records == ("1.2.3.4",)
        assert snap.mx_records == ()
        assert snap.ns_records == ("ns1.x",)


class TestDnsSnapshotSerialization:
    def test_round_trips_through_dict(self):
        original = DnsSnapshot(
            a_records=("1.2.3.4",), mx_records=("mail.x",), ns_records=("ns1.x",)
        )
        restored = DnsSnapshot.from_dict(original.to_dict())
        assert restored == original

    def test_from_empty_dict_is_empty_snapshot(self):
        assert DnsSnapshot.from_dict(None) == DnsSnapshot()
        assert DnsSnapshot.from_dict({}) == DnsSnapshot()
