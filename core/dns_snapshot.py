"""DNS record snapshots — data acquisition for incident detection (the
finding history / escalation timeline). A domain's A/MX/NS records
changing over time is a real signal (parked → pointed at hosting, mail
server added, nameservers moved to a different registrar/host) that a
single point-in-time registration check misses entirely.

Fails closed like every other core/ module: a lookup failure returns an
empty snapshot, never an exception — the worker treats "couldn't compare"
differently from "compared and nothing changed" (see
worker/pipeline.py's incident-detection helper).
"""

from dataclasses import dataclass

import dns.resolver


@dataclass(frozen=True)
class DnsSnapshot:
    a_records: tuple[str, ...] = ()
    mx_records: tuple[str, ...] = ()
    ns_records: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "a": list(self.a_records),
            "mx": list(self.mx_records),
            "ns": list(self.ns_records),
        }

    @classmethod
    def from_dict(cls, data: dict | None) -> "DnsSnapshot":
        if not data:
            return cls()
        return cls(
            a_records=tuple(data.get("a", [])),
            mx_records=tuple(data.get("mx", [])),
            ns_records=tuple(data.get("ns", [])),
        )


def _resolve(domain: str, record_type: str, timeout: float) -> tuple[str, ...]:
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=timeout)
        return tuple(sorted(str(r).rstrip(".") for r in answers))
    except Exception:
        return ()


def get_dns_snapshot(domain: str, timeout: float = 5.0) -> DnsSnapshot:
    """Best-effort snapshot — each record type is resolved independently,
    so a missing MX record (most domains have none) doesn't blank out
    the A/NS records that did resolve."""
    return DnsSnapshot(
        a_records=_resolve(domain, "A", timeout),
        mx_records=_resolve(domain, "MX", timeout),
        ns_records=_resolve(domain, "NS", timeout),
    )
