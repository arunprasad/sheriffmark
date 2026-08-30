"""DNSBL (DNS-based blackhole list) lookups — checks whether a
domain's resolved IP addresses are already known to a public abuse/
spam network, adding that signal to what's recorded about a finding.

Same "it's just a DNS query" mechanism as everything else in this
project's registration/whois family (RDAP's rdap.org bootstrap, IANA's
whois bootstrap): no API key, no account, no per-provider client
library — a DNSBL lookup is a reversed-IP subdomain query against the
list's own zone, answered like any other DNS record.

Checks two public lists rather than one, queried independently so
either failing doesn't blank out the other:
- Barracuda Central (b.barracudacentral.org)
- SpamCop (bl.spamcop.net)

**Deliberately not Spamhaus's zen.spamhaus.org**, despite being the
most commonly cited public DNSBL: confirmed live (querying their own
documented self-test entry, `2.0.0.127.zen.spamhaus.org`, which must
always resolve as listed if the DNSBL is reachable at all) that
Spamhaus's free public DNSBL returns NXDOMAIN — not "not listed", the
zone refuses to answer — when queried from this project's actual
deployment environment: a cloud/datacenter IP range. That's Spamhaus's
own documented policy (see their DNSBL usage terms), not a bug on
either side — they steer commercial/automated/datacenter queriers
toward a paid Data Query Service instead of the free public zone. Since
self-hosting this project on a VPS/cloud instance is the primary
deployment model, building on a list that's known not to answer from
that exact environment would ship a silently-broken feature for most
real users. Barracuda and SpamCop were verified live from the same
environment and both answered correctly.

Fails closed like every other module in this family: any failure
(malformed IP, resolution error, timeout, a list being unreachable or
blocking this query) returns "not listed" for that list rather than
raising — an outage degrades to less corroboration, not a crashed run.
"""

import ipaddress

import dns.resolver

DNSBL_HOSTS = {
    "barracuda": "b.barracudacentral.org",
    "spamcop": "bl.spamcop.net",
}


def _reverse_ipv4(ip: str) -> str | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version != 4:
        # Both lists here are IPv4-only zones — an IPv6 finding simply
        # doesn't get this signal, not an error.
        return None
    return ".".join(reversed(ip.split(".")))


def check_ip_blocklist(ip: str, host: str, timeout: float = 3.0) -> list[str]:
    """Returns the raw DNSBL response codes for `ip` against `host`
    (one of `DNSBL_HOSTS`'s values — e.g. ["127.0.0.2"]), or `[]` if
    it isn't listed, isn't IPv4, or the lookup itself fails."""
    reversed_ip = _reverse_ipv4(ip)
    if reversed_ip is None:
        return []
    query = f"{reversed_ip}.{host}"
    try:
        answers = dns.resolver.resolve(query, "A", lifetime=timeout)
        return sorted(str(r) for r in answers)
    except dns.resolver.NXDOMAIN:
        return []  # not listed — the expected common case
    except Exception:
        return []


def check_domain_blocklist(a_records: list[str] | tuple[str, ...], timeout: float = 3.0) -> dict:
    """Checks every A record in `a_records` against both configured
    DNSBLs. Returns `{ip: {list_name: [return_codes]}}` for any IP
    flagged by at least one list — an empty dict if none are, which is
    the common case for the vast majority of findings."""
    hits: dict = {}
    for ip in a_records:
        for list_name, host in DNSBL_HOSTS.items():
            codes = check_ip_blocklist(ip, host, timeout=timeout)
            if codes:
                hits.setdefault(ip, {})[list_name] = codes
    return hits
