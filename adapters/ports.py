"""Interfaces `worker/` (and later `web/`) code against, so swapping the
concrete implementation — a different SMTP provider, eventually a
different DB — never touches orchestration logic in `worker/pipeline.py`.

Storage doesn't get a formal Protocol yet: `adapters/storage_postgres.py`
is a thin, direct SQLAlchemy repository, and SQLAlchemy itself is already
the portable choice (see shared/models.py's portable column types) —
there's no concrete second backend anticipated that would justify the
extra indirection right now. Notifier does get one: swapping SMTP
providers (Resend/SES/Mailgun)
is a real, near-term scenario, and the interface is small enough that
formalizing it costs nothing.
"""

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class FindingSummary:
    """What a digest email needs to know about one new finding —
    deliberately not the ORM `Finding` object, so the notifier has no
    dependency on `shared.models`."""

    domain: str
    brand_name: str
    source: str  # "generated" | "ct"
    status: str
    risk_score: int | None
    risk_bucket: str | None


class Notifier(Protocol):
    """`destination` means whatever the implementation needs to route a
    message: an email address for `SmtpNotifier`, a webhook URL for
    `SlackNotifier`/`DiscordNotifier`/`WebhookNotifier`. Called
    positionally everywhere, so the parameter name itself isn't load-
    bearing — kept generic so one Protocol covers every channel."""

    def send_digest(
        self, destination: str, tenant_name: str, findings: list[FindingSummary]
    ) -> None: ...
