"""Domain registration status: a cheap DNS pre-check, with RDAP as the
authoritative fallback when DNS is ambiguous, and legacy whois:43 as a
last resort where RDAP itself is unavailable.

Evolves the approach in ../check_domains.py:
- DNS stage is unchanged in spirit (single UDP NS query against an
  authoritative nameserver for the TLD) — cheap, and answers most cases
  outright without touching RDAP at all.
- RDAP stage now goes through rdap.org's bootstrap redirector instead of
  a hardcoded Verisign endpoint, so this works across TLDs (any TLD IANA
  has delegated) without a per-registry URL map to maintain.
- Whois stage exists because plenty of ccTLD registries still don't run
  RDAP at all (users specifically want their own ccTLDs monitored, not
  just .com/.net/.org). It's a deliberately last-resort fallback, not a
  peer of RDAP: whois has no structured response format, so
  "registered" vs "unregistered" is a heuristic phrase match and
  registrar/created-date extraction is best-effort regex, not a parsed
  schema. Expect it to be less reliable than RDAP, not equally so — see
  `whois_lookup`'s docstring.

Every function here fails closed (`status="unknown"`) rather than
raising, so a flaky nameserver, RDAP outage, or whois failure degrades
one candidate's result instead of crashing the run.
"""

import re
import socket
from dataclasses import dataclass
from datetime import date, datetime

import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver
import requests

from shared.http_utils import parse_retry_after

USER_AGENT = "DomainNameWatch/1.0 (+mailto:ops@example.com)"
RDAP_BOOTSTRAP_URL = "https://rdap.org/domain/{domain}"


@dataclass(frozen=True)
class RegistrationStatus:
    status: str  # "registered" | "unregistered" | "unknown"
    registrar: str | None = None
    created_date: date | None = None
    # The registrar/registry's abuse-reporting contact, if the RDAP
    # (or whois) response includes one — recorded so a takedown report
    # doesn't require a separate manual lookup, but this project stops
    # at recording it: no draft generation, no auto-filing — that stays
    # a human's decision.
    abuse_email: str | None = None
    # A 429 was previously indistinguishable from any other non-200/404
    # RDAP response — both collapsed into status="unknown", silently
    # discarding the one signal that actually tells the caller *why*
    # ("we're being throttled") and *what to do about it* (back off,
    # don't just keep hammering every remaining candidate). See
    # worker/pipeline.py's RateLimiter for how these get acted on.
    rate_limited: bool = False
    retry_after_seconds: float | None = None


def load_tld_nameservers(tld: str) -> list[tuple[str, str]]:
    """Resolve the authoritative nameservers for `tld` once; the result is
    meant to be reused across many domain checks under that TLD rather
    than re-resolved per domain (matches the original script's approach)."""
    servers: list[tuple[str, str]] = []
    try:
        ns_hosts = [str(rr.target) for rr in dns.resolver.resolve(tld + ".", "NS")]
    except Exception:
        return servers

    for host in ns_hosts:
        try:
            ip = dns.resolver.resolve(host, "A")[0].to_text()
            servers.append((host, ip))
        except Exception:
            continue
    return servers


def rdap_lookup(
    domain: str, session: requests.Session | None = None, timeout: float = 8.0
) -> RegistrationStatus:
    """Authoritative check via RDAP, routed through rdap.org's bootstrap
    redirector so this isn't tied to any one TLD's registry."""
    http = session or requests
    try:
        resp = http.get(
            RDAP_BOOTSTRAP_URL.format(domain=domain),
            timeout=timeout,
            headers={"User-Agent": USER_AGENT},
        )
    except requests.RequestException:
        return RegistrationStatus(status="unknown")

    if resp.status_code == 404:
        # rdap.org itself returns 404 for two entirely different
        # reasons, distinguishable only by the body: a real registry
        # saying "this domain isn't registered" (body empty, e.g.
        # Verisign for .net — or the registry's own structured
        # not-found JSON, e.g. .org's) vs rdap.org's *own* bootstrap
        # layer having no RDAP route for this TLD at all, body
        # `{"errorCode":404,"title":"No RDAP service is available for
        # this resource"}` — confirmed live against .de (DENIC has no
        # public RDAP) and, surprisingly, .io too (rdap.org's bootstrap
        # table is itself incomplete/stale, not just genuinely-RDAP-
        # less TLDs). Treating that second case as "unregistered" would
        # both be wrong and would suppress the whois fallback below
        # from ever running for exactly the TLDs it exists for.
        try:
            body = resp.json()
        except ValueError:
            body = {}
        if "no rdap service" in str(body.get("title", "")).lower():
            return RegistrationStatus(status="unknown")
        return RegistrationStatus(status="unregistered")
    if resp.status_code == 429:
        return RegistrationStatus(
            status="unknown",
            rate_limited=True,
            retry_after_seconds=parse_retry_after(resp.headers.get("Retry-After")),
        )
    if resp.status_code != 200:
        return RegistrationStatus(status="unknown")

    try:
        data = resp.json()
    except ValueError:
        return RegistrationStatus(status="unknown")

    return RegistrationStatus(
        status="registered",
        registrar=_extract_registrar(data),
        created_date=_extract_created_date(data),
        abuse_email=_extract_abuse_email(data),
    )


def has_mx_records(domain: str, timeout: float = 5.0) -> bool:
    """Cheap signal for risk scoring: mail configured on a lookalike
    domain is a strong indicator of active phishing infrastructure."""
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=timeout)
        return len(answers) > 0
    except Exception:
        return False


def _rdap_or_whois(domain: str, whois_host: str | None) -> RegistrationStatus:
    """Try RDAP first, always — it's structured and authoritative where
    it exists. Only reach for whois when RDAP came back genuinely
    unknown (not rate-limited — that's a "back off and retry RDAP
    later" signal, not "this TLD doesn't have RDAP")."""
    result = rdap_lookup(domain)
    if result.status != "unknown" or result.rate_limited:
        return result
    return whois_lookup(domain, whois_host)


def check_registration(
    domain: str,
    ns_servers: list[tuple[str, str]],
    whois_host: str | None = None,
    ns_index: int = 0,
) -> RegistrationStatus:
    """Cheap DNS pre-check against one authoritative NS, but RDAP/whois
    always gets a look at anything the DNS check finds registered — the
    DNS-only shortcut this evolved from (check_domains.py's
    domain_availability_v1) was built purely to answer "is this
    available to register," where a bare "registered" was the whole
    answer and nothing further was needed. This project's actual job
    starts *after* that: find registered candidates, then assess risk
    (registrar, abuse contact, creation date) — data only RDAP/whois
    carries. Skipping that lookup because DNS already said "registered"
    would silently blank out exactly the enrichment a real, live squat
    (the kind that has working DNS delegation, because a phishing site
    needs to actually resolve) is worth finding in the first place.

    DNS delegation existing at the registry's own authoritative
    nameserver is still treated as the authoritative registration
    signal, though — if RDAP/whois momentarily disagrees or is
    unreachable, the DNS-confirmed "registered" stands and only the
    enrichment fields are merged in from whatever RDAP/whois returned.

    `whois_host` is the registry's whois:43 host for this domain's TLD
    (from `load_tld_whois_host`), resolved and cached once per TLD by
    the caller — same pattern as `ns_servers`/`load_tld_nameservers`.
    Pass None if it's not known to skip the whois fallback entirely."""
    if not ns_servers:
        return RegistrationStatus(status="unknown")

    ns_host, ns_ip = ns_servers[ns_index % len(ns_servers)]
    query = dns.message.make_query(domain, dns.rdatatype.NS, want_dnssec=False)
    query.flags &= ~dns.flags.RD

    try:
        resp = dns.query.udp(query, ns_ip, timeout=3)
    except Exception:
        return RegistrationStatus(status="unknown")

    if resp.rcode() == dns.rcode.NXDOMAIN:
        return _rdap_or_whois(domain, whois_host)

    for rrset in resp.authority:
        if rrset.rdtype == dns.rdatatype.NS:
            enrichment = _rdap_or_whois(domain, whois_host)
            if enrichment.rate_limited:
                # Not actually enriched this round — the caller treats
                # a rate-limited result as "not checked yet, retry
                # next run" regardless of `status`, so there's no risk
                # of this DNS-confirmed registration getting dropped;
                # it'll come back around once RDAP is available again.
                return enrichment
            return RegistrationStatus(
                status="registered",
                registrar=enrichment.registrar,
                created_date=enrichment.created_date,
                abuse_email=enrichment.abuse_email,
            )
        if rrset.rdtype == dns.rdatatype.SOA:
            return _rdap_or_whois(domain, whois_host)

    return RegistrationStatus(status="unknown")


def _extract_registrar(rdap_data: dict) -> str | None:
    for entity in rdap_data.get("entities", []):
        if "registrar" not in entity.get("roles", []):
            continue
        for item in entity.get("vcardArray", [None, []])[1]:
            if item and item[0] == "fn":
                return item[3]
    return None


def _extract_created_date(rdap_data: dict) -> date | None:
    for event in rdap_data.get("events", []):
        if event.get("eventAction") != "registration":
            continue
        try:
            return datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00")).date()
        except (KeyError, ValueError):
            return None


def _abuse_email_from_entity(entity: dict) -> str | None:
    if "abuse" not in entity.get("roles", []):
        return None
    for item in entity.get("vcardArray", [None, []])[1]:
        if item and item[0] == "email":
            return item[3]
    return None


def _extract_abuse_email(rdap_data: dict) -> str | None:
    """Per ICANN's RDAP response profile, the abuse contact is usually
    its own entity *nested inside* the registrar entity's `entities`
    list, not a top-level entity — but some registries put it at the
    top level instead, so both shapes are checked rather than assuming
    one."""
    for entity in rdap_data.get("entities", []):
        email = _abuse_email_from_entity(entity)
        if email:
            return email
        for nested in entity.get("entities", []):
            email = _abuse_email_from_entity(nested)
            if email:
                return email
    return None


IANA_WHOIS_HOST = "whois.iana.org"

# Common "no match" phrasing across registries — necessarily a partial
# list, not an exhaustive one: whois has no standard response schema
# (unlike RDAP's JSON), so every registry writes its own wording. A
# registry whose phrasing isn't covered here will misreport an
# unregistered domain as "registered" with no registrar/created_date
# (the response body doesn't match any of the extraction patterns
# below either, so nothing false gets fabricated) rather than the
# other way around — a missed "unregistered" signal is a one-scan
# delay until it's rechecked, a false "unregistered" would mean a real
# squat gets silently dropped forever.
_WHOIS_NOT_FOUND_PHRASES = (
    "no match",
    "not found",
    "no data found",
    "no entries found",
    "no matching record",
    "no object found",
    "domain not found",
    "object does not exist",
    "nothing found",
    "status: available",
    "status: free",
    "is available for registration",
)

_WHOIS_REGISTRAR_RE = re.compile(r"(?im)^\s*registrar(?:\s*name)?\s*:\s*(.+?)\s*$")
_WHOIS_CREATED_DATE_RE = re.compile(
    r"(?im)^\s*(?:creation date|created(?:\s*on)?|registered(?:\s*on)?"
    r"|domain registration date|registration time)\s*:\s*(.+?)\s*$"
)
# "registrar abuse contact email" (the standard ICANN gTLD whois field)
# checked before the shorter "abuse ... email"/"abuse-mailbox" forms
# some ccTLD/RIR-style registries use, so the more specific label wins
# when a response happens to contain both.
_WHOIS_ABUSE_EMAIL_RE = re.compile(
    r"(?im)^\s*(?:registrar abuse contact email|abuse contact email"
    r"|abuse-mailbox|abuse email)\s*:\s*(\S+@\S+?)\s*$"
)
_WHOIS_DATE_FORMATS = (
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d",
    "%d-%b-%Y",
    "%d.%m.%Y",
    "%Y.%m.%d",
    "%Y/%m/%d",
)


def _whois_query(host: str, query: str, timeout: float) -> str:
    """Raw whois:43 request-response — a plain-text protocol with no
    framing beyond "the server closes the connection when it's done
    talking". Lets OSError (timeout, connection refused, DNS failure
    resolving `host`, ...) propagate; every caller here catches it."""
    with socket.create_connection((host, 43), timeout=timeout) as sock:
        sock.sendall(f"{query}\r\n".encode())
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace")


def load_tld_whois_host(tld: str, timeout: float = 5.0) -> str | None:
    """Ask IANA which whois:43 server is authoritative for `tld` —
    the whois-protocol equivalent of RDAP's bootstrap redirector, so
    this needs no hardcoded per-registry host table either. Returns
    None if IANA has no referral for this TLD (plenty of ccTLDs run
    neither RDAP nor whois publicly) or the lookup itself fails.

    Meant to be resolved once per TLD and reused across every
    candidate under it, same as `load_tld_nameservers` — repeating
    this per-domain would multiply load on whois.iana.org for no
    benefit, since the answer for a given TLD doesn't change."""
    try:
        response = _whois_query(IANA_WHOIS_HOST, tld, timeout=timeout)
    except OSError:
        return None
    # IANA's TLD-level records use a "whois:" field for the registry's
    # own server (confirmed against live whois.iana.org responses for
    # .de/.jp/.cc/.ai/.io — "refer:" is a whois-protocol convention
    # used elsewhere, e.g. by some registries at the domain level, but
    # not what IANA's own TLD records carry).
    for line in response.splitlines():
        if line.lower().startswith("whois:"):
            return line.split(":", 1)[1].strip()
    return None


def _extract_whois_registrar(text: str) -> str | None:
    match = _WHOIS_REGISTRAR_RE.search(text)
    return match.group(1).strip() or None if match else None


def _extract_whois_created_date(text: str) -> date | None:
    match = _WHOIS_CREATED_DATE_RE.search(text)
    if not match:
        return None
    raw = match.group(1).strip()
    candidates = [raw, raw.split()[0]] if " " in raw else [raw]
    for candidate in candidates:
        for fmt in _WHOIS_DATE_FORMATS:
            try:
                return datetime.strptime(candidate, fmt).date()
            except ValueError:
                continue
    return None


def _extract_whois_abuse_email(text: str) -> str | None:
    match = _WHOIS_ABUSE_EMAIL_RE.search(text)
    return match.group(1).strip() if match else None


def whois_lookup(domain: str, whois_host: str | None, timeout: float = 5.0) -> RegistrationStatus:
    """Last-resort fallback for TLDs whose registry doesn't publish
    RDAP — most ccTLDs still only speak the older whois:43 protocol.
    Unlike `rdap_lookup`'s structured JSON, whois responses are free
    text with no standard schema across registries, so:

    - "registered" vs "unregistered" is a heuristic phrase match
      (`_WHOIS_NOT_FOUND_PHRASES`), not a clean 404.
    - registrar/created_date/abuse_email extraction is best-effort
      regex over a handful of common field labels, not a parsed
      schema — expect more `None`s here than from RDAP, and don't
      treat an extracted value as more authoritative than it is.

    `whois_host` is the registry's whois host for this domain's TLD —
    pass None (no known host) to skip straight to "unknown" without a
    wasted connection attempt."""
    if whois_host is None:
        return RegistrationStatus(status="unknown")
    try:
        response = _whois_query(whois_host, domain, timeout=timeout)
    except OSError:
        return RegistrationStatus(status="unknown")

    if not response.strip():
        return RegistrationStatus(status="unknown")

    lower = response.lower()
    if any(phrase in lower for phrase in _WHOIS_NOT_FOUND_PHRASES):
        return RegistrationStatus(status="unregistered")

    return RegistrationStatus(
        status="registered",
        registrar=_extract_whois_registrar(response),
        created_date=_extract_whois_created_date(response),
        abuse_email=_extract_whois_abuse_email(response),
    )
