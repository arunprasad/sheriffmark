"""The full data model, built now even though only the `free` plan is real.

This is the decision that lets every later phase (dashboard, billing,
Standard/Pro features) be additive — new rows and new columns, never a
restructure.
"""

import uuid
from datetime import UTC, date, datetime

from sqlalchemy import (
    JSON,
    Date,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    String,
    TypeDecorator,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY as PG_ARRAY
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from shared.db import Base

# Portable column types: SQLite (the default store — see shared/config.py)
# has no array type and no first-class JSONB, so both of these fall back
# to plain JSON there, while an existing or future Postgres deployment
# keeps its native, indexable type unchanged (`.with_variant` only swaps
# the DDL/storage, never the Python-side value — every read/write here
# already treats these columns as a whole dict/list, never queried into
# with a Postgres-specific operator like `->`/`@>`/`ANY`, so the swap is
# transparent to every caller).
JSONBlob = JSON().with_variant(JSONB(), "postgresql")
StringList = JSON().with_variant(PG_ARRAY(String()), "postgresql")


def _utcnow() -> datetime:
    """Client-side (Python) default for every timestamp column below,
    alongside the DB-side `server_default=func.now()` that's kept as a
    fallback for the rare row inserted via raw SQL rather than the ORM.
    Needed for two real, SQLite-specific reasons — neither applies to
    Postgres, which already does the right thing natively:

    1. SQLite's CURRENT_TIMESTAMP (what `func.now()` compiles to there)
       only has *second* resolution — two rows inserted in the same
       wall-clock second get identical timestamps, breaking any
       "newest first" ordering that assumes distinct values. A
       Python-computed datetime has microsecond resolution.
    2. This value is always attached at INSERT time (SQLAlchemy sends it
       explicitly), so `server_default` never actually fires for
       ORM-driven inserts — only for the odd raw-SQL row.
    """
    return datetime.now(UTC)


class UTCDateTime(TypeDecorator):
    """`DateTime(timezone=True)` round-trips fine through Postgres
    (native tz-aware storage) but SQLite has no timezone-aware datetime
    type at all — it silently comes back *naive* on read regardless of
    what was written (confirmed: even a value set with
    `datetime.now(UTC)` from Python, not a server default, loses its
    tzinfo through SQLite). Every timestamp in this schema is UTC by
    convention, so this just re-attaches that known timezone on the way
    out for dialects that dropped it. A no-op on Postgres, which never
    loses it in the first place."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_result_value(self, value, dialect):
        if value is not None and value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value


class Plan(Base):
    """Pricing/feature tier. `limits` is deliberately a flexible bag of
    values rather than fixed columns — the pricing formula (per-brand,
    usage-based, feature-gated) is undecided on purpose; this schema
    supports any of them without a migration."""

    __tablename__ = "plans"

    plan_id: Mapped[str] = mapped_column(String, primary_key=True)  # e.g. "free"
    name: Mapped[str] = mapped_column(String, nullable=False)
    limits: Mapped[dict] = mapped_column(JSONBlob, nullable=False, default=dict)

    tenants: Mapped[list["Tenant"]] = relationship(back_populates="plan")


class Tenant(Base):
    __tablename__ = "tenants"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String, nullable=False)
    plan_id: Mapped[str] = mapped_column(
        ForeignKey("plans.plan_id"), nullable=False, default="free"
    )
    stripe_customer_id: Mapped[str | None] = mapped_column(String, nullable=True)
    # Stop-gap until real managed-auth-derived user emails are wired up —
    # the worker needs somewhere to send the digest to today. Additive;
    # this can stay as a fallback/default digest recipient once real
    # per-user emails exist via the auth provider.
    contact_email: Mapped[str | None] = mapped_column(String, nullable=True)
    # Per-tenant destinations for non-email channels — keys:
    # "slack_webhook_url", "discord_webhook_url", "webhook_url". A
    # missing/empty key means that channel isn't configured for this
    # tenant; see worker/pipeline.py's dispatch_notifications().
    notification_channels: Mapped[dict] = mapped_column(JSONBlob, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime, server_default=func.now(), default=_utcnow
    )

    plan: Mapped["Plan"] = relationship(back_populates="tenants")
    brands: Mapped[list["Brand"]] = relationship(back_populates="tenant")
    users: Mapped[list["User"]] = relationship(back_populates="tenant")


class User(Base):
    """Thin mapping table only — the managed auth provider owns
    credentials, sessions, everything else. This table just links an
    external identity to a tenant and a role."""

    __tablename__ = "users"

    external_id: Mapped[str] = mapped_column(String, primary_key=True)  # id from auth provider
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("tenants.tenant_id"), index=True
    )
    role: Mapped[str] = mapped_column(String, nullable=False, default="owner")

    tenant: Mapped["Tenant"] = relationship(back_populates="users")


class LocalCredential(Base):
    """Email/password credential for the built-in local auth provider.
    Deliberately separate from `User` — `User` is the provider-agnostic
    identity/tenant mapping (an external_id can come from local, OIDC, or
    SAML), while this table is where actual secrets and provider-specific
    verification state live. `external_id` is formatted "local:<uuid>" to
    keep the id namespace collision-free across providers (see
    web/api/local_auth.py)."""

    __tablename__ = "local_credentials"

    external_id: Mapped[str] = mapped_column(String, primary_key=True)
    email: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(String, nullable=False)
    # True immediately when SMTP isn't configured at signup time (nothing
    # to verify with); False until the emailed link is clicked when it is.
    # See Settings.smtp_configured.
    email_verified: Mapped[bool] = mapped_column(default=True)
    verification_token: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime, server_default=func.now(), default=_utcnow
    )


class SigningKey(Base):
    """The local auth provider's own JWT signing keypair (RS256),
    generated on first use and persisted here so it survives restarts
    without needing a mounted secret volume — see
    web/api/crypto_keys.py. `kid` is the JWT header key id, letting the
    local JWKS endpoint (and a future key-rotation pass) publish more
    than one valid public key at a time."""

    __tablename__ = "signing_keys"

    kid: Mapped[str] = mapped_column(String, primary_key=True)
    private_key_pem: Mapped[str] = mapped_column(String, nullable=False)
    public_key_pem: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime, server_default=func.now(), default=_utcnow
    )


class Brand(Base):
    __tablename__ = "brands"

    brand_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("tenants.tenant_id"), index=True
    )
    name: Mapped[str] = mapped_column(String, nullable=False)
    keywords: Mapped[list[str]] = mapped_column(StringList, nullable=False, default=list)
    tlds: Mapped[list[str]] = mapped_column(StringList, nullable=False, default=list)
    variant_rules: Mapped[list[str]] = mapped_column(StringList, nullable=False, default=list)
    active: Mapped[bool] = mapped_column(default=True)
    # Cursor for incremental CT log polling (core/ct_poller.py) — the
    # highest crt.sh certificate id seen for this brand on the last
    # successful poll. NULL means "never successfully polled".
    ct_last_cert_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Manual watchlist: exact domains a user explicitly wants monitored,
    # for when dnstwist's algorithmic generation misses one. Checked by
    # the worker the same way as generated candidates, tagged
    # findings.source="manual". See worker/pipeline.py's
    # process_brand_custom.
    custom_domains: Mapped[list[str]] = mapped_column(StringList, nullable=False, default=list)
    # Domains the tenant already legitimately owns (defensive
    # registrations, secondary brand domains, etc.) — opposite purpose
    # from custom_domains: these seed typosquat generation too (a
    # squat of an owned domain is worth catching, not just a squat of
    # the primary brand name), but are filtered out of every detection
    # path's results, since the domain itself is legitimate, not a
    # threat. See worker/pipeline.py's process_brand_generated.
    owned_domains: Mapped[list[str]] = mapped_column(StringList, nullable=False, default=list)
    # Resume checkpoints for the generated-candidates / custom-domains
    # scan loops (worker/pipeline.py) — the last candidate domain
    # successfully checked. Set when a run stops mid-list (graceful
    # shutdown or a rate limit — see RateLimiter), cleared when a full
    # pass completes, so the next scheduled run either continues where
    # this one left off or starts a fresh full pass. NULL means "start
    # from the beginning."
    generated_scan_cursor: Mapped[str | None] = mapped_column(String, nullable=True)
    custom_scan_cursor: Mapped[str | None] = mapped_column(String, nullable=True)
    # When the *current* (possibly still-resuming) pass began — not
    # when the cursor was last updated. Lets the worker tell "this pass
    # has been dragging on across repeated interruptions for over a
    # day" from "this pass just started" and discard stale progress
    # rather than keep deferring an already-day-old partial scan
    # indefinitely. Cleared alongside the cursor, whether that's a
    # completed pass or a staleness-triggered restart. See
    # worker/pipeline.py's _is_scan_stale.
    generated_scan_started_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    custom_scan_started_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    # When the generated-candidates path last ran every candidate to
    # completion — the UI's "last completed scan" freshness signal.
    # Deliberately tied to the generated path specifically (the
    # dominant, most representative scan), not stamped on every worker
    # touch of this brand — a brand stuck resuming across rate-limit
    # interruptions should visibly show a stale last-completed date,
    # not "just now" every time the worker merely attempts it.
    last_scan_completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    tenant: Mapped["Tenant"] = relationship(back_populates="brands")
    findings: Mapped[list["Finding"]] = relationship(back_populates="brand")


class Finding(Base):
    """Composite PK (brand_id, domain) — not domain alone. Two different
    tenants' brands can legitimately generate the same candidate string
    (e.g. both configure a generic keyword that produces
    "example-login.com"); a domain-only PK would let one tenant's write
    collide with another's. Corrected here at the source since this table
    had never been deployed against a live DB at the time this was fixed."""

    __tablename__ = "findings"

    domain: Mapped[str] = mapped_column(String, primary_key=True)
    brand_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("brands.brand_id"), primary_key=True, index=True
    )
    # "generated" | "ct" | "manual" (custom-domains watchlist) |
    # "on_demand" (worker/pipeline.py's run_on_demand_scan)
    source: Mapped[str] = mapped_column(String, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(
        UTCDateTime, server_default=func.now(), default=_utcnow
    )
    last_checked: Mapped[datetime] = mapped_column(
        UTCDateTime, server_default=func.now(), default=_utcnow
    )
    # "registered" | "unregistered" | "unknown"
    status: Mapped[str] = mapped_column(String, nullable=False)
    registrar: Mapped[str | None] = mapped_column(String, nullable=True)
    created_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    # The registrar/registry's abuse-reporting contact (RDAP/whois),
    # recorded so a takedown report doesn't need a separate manual
    # lookup — recording only, no draft/auto-file (see
    # core/registration.py's RegistrationStatus.abuse_email docstring).
    abuse_email: Mapped[str | None] = mapped_column(String, nullable=True)
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    risk_factors: Mapped[list[str]] = mapped_column(StringList, nullable=False, default=list)
    alerted_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    # Latest acquired snapshot, stored so the next run has something to
    # diff against without a separate lookup — see core/dns_snapshot.py,
    # core/crawler.py, and worker/pipeline.py's incident detection.
    dns_snapshot: Mapped[dict] = mapped_column(JSONBlob, nullable=False, default=dict)
    website_snapshot: Mapped[dict] = mapped_column(JSONBlob, nullable=False, default=dict)
    # Captured once on first registration, then only re-captured when
    # website_snapshot.content_hash changes — not every scan, to keep
    # Playwright launches bounded to "new or changed sites." See
    # core/screenshot.py, worker/pipeline.py's capture trigger.
    screenshot_data: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    screenshot_content_type: Mapped[str | None] = mapped_column(String, nullable=True)
    screenshot_captured_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    # Manual resolution workflow — deliberately separate from `status`
    # above, which is the DNS/RDAP registration state, not a workflow
    # state. "resolved_owned" (claimed as an owned domain) is tracked
    # distinctly from a plain "resolved" (took it down, confirmed
    # benign, etc.) by explicit user request — the two mean genuinely
    # different things for reporting ("how many did we actually get
    # taken down" vs "how many turned out to be ours all along") even
    # though both close the finding out. "resolution_failed" stays
    # counted as unresolved — it's a record that an attempt was made,
    # not that the threat went away. Every transition also gets its own
    # FindingEvent (see worker equivalents: "resolved", "resolved_owned",
    # "resolution_failed", "reopened"), so the incident timeline stays
    # the single source of truth for *when* and *why*, not just *what
    # it is now*.
    resolution_status: Mapped[str] = mapped_column(String, nullable=False, default="open")
    resolution_note: Mapped[str | None] = mapped_column(String, nullable=True)

    brand: Mapped["Brand"] = relationship(back_populates="findings")


class FindingEvent(Base):
    """One row per detected change on a finding — WHOIS change, DNS
    change, website content change, form/password-field detected,
    cross-domain redirect detected. This is what makes a finding a
    trackable *incident* with a timeline, not just a point-in-time
    snapshot. `details` shape varies by `event_type` (see
    worker/pipeline.py's incident-detection helper for the exact
    payloads each type carries)."""

    __tablename__ = "finding_events"
    __table_args__ = (
        # Composite FK back to findings' own composite PK (domain,
        # brand_id) — every event must belong to a real, still-existing
        # finding, on top of the plain brand_id -> brands FK below.
        ForeignKeyConstraint(
            ["domain", "brand_id"],
            ["findings.domain", "findings.brand_id"],
            name="fk_finding_events_finding",
        ),
        Index("ix_finding_events_domain_brand", "domain", "brand_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    brand_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("brands.brand_id"))
    domain: Mapped[str] = mapped_column(String, nullable=False)
    event_type: Mapped[str] = mapped_column(String, nullable=False)
    detected_at: Mapped[datetime] = mapped_column(
        UTCDateTime, server_default=func.now(), default=_utcnow, index=True
    )
    details: Mapped[dict] = mapped_column(JSONBlob, nullable=False, default=dict)


class ReferenceImage(Base):
    """A user-uploaded logo or real-site screenshot for one brand, used
    as the comparison target for visual similarity detection
    (core/visual_similarity.py). Stored directly in the app's own
    database (bytea on Postgres, a BLOB on the SQLite default) — a
    handful of images per brand, size-capped at upload
    (web/api/routes/brands.py) — rather than adding an object-storage
    dependency for what's a small, bounded volume of data. Consistent
    with this project's "no cloud-specific storage" approach."""

    __tablename__ = "reference_images"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    brand_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("brands.brand_id"), nullable=False, index=True
    )
    kind: Mapped[str] = mapped_column(String, nullable=False)  # "logo" | "site_screenshot"
    filename: Mapped[str | None] = mapped_column(String, nullable=True)
    content_type: Mapped[str] = mapped_column(String, nullable=False)
    image_data: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime, server_default=func.now(), default=_utcnow
    )


class CrawledPage(Base):
    """One page discovered by the site-graph crawler (core/site_spider.py)
    for a registered finding. Deliberately structural, not a content
    store — `content_hash` plus the server's own `Last-Modified`/`ETag`
    (stored as the raw header strings the server sent, not reparsed —
    servers aren't always RFC-compliant, and the raw value is all a diff
    needs) are what change-detection needs; the actual page body is never
    persisted."""

    __tablename__ = "crawled_pages"
    __table_args__ = (
        # Composite FK back to findings' own composite PK (domain,
        # brand_id), on top of the plain brand_id -> brands FK below —
        # same pattern as FindingEvent.
        ForeignKeyConstraint(
            ["domain", "brand_id"],
            ["findings.domain", "findings.brand_id"],
            name="fk_crawled_pages_finding",
        ),
        UniqueConstraint("domain", "brand_id", "url", name="uq_crawled_pages_domain_brand_url"),
        Index("ix_crawled_pages_domain_brand", "domain", "brand_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    brand_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("brands.brand_id"))
    domain: Mapped[str] = mapped_column(String, nullable=False)
    url: Mapped[str] = mapped_column(String, nullable=False)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    content_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    last_modified: Mapped[str | None] = mapped_column(String, nullable=True)
    etag: Mapped[str | None] = mapped_column(String, nullable=True)
    title: Mapped[str | None] = mapped_column(String, nullable=True)
    has_forms: Mapped[bool] = mapped_column(default=False)
    form_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    has_password_field: Mapped[bool] = mapped_column(default=False)
    # Neither this crawler nor core/site_spider.py execute JavaScript —
    # a client-rendered SPA mounting into an empty shell reads as blank
    # content to both. See core/spa_detection.py: flagged here (not
    # fixed here) so it's visible for prioritizing a future headless-
    # browser crawler, rather than silently logged as "no content."
    is_spa: Mapped[bool] = mapped_column(default=False)
    spa_signals: Mapped[list[str]] = mapped_column(StringList, nullable=False, default=list)
    first_seen: Mapped[datetime] = mapped_column(
        UTCDateTime, server_default=func.now(), default=_utcnow
    )
    last_checked: Mapped[datetime] = mapped_column(
        UTCDateTime, server_default=func.now(), default=_utcnow
    )


class PageLink(Base):
    """One edge in a finding's crawled site graph — `from_url` links to
    `to_url`. `is_external` marks a link leaving the crawled domain
    (recorded for the graph, never followed further — see
    core/site_spider.py's depth/domain bounds)."""

    __tablename__ = "page_links"
    __table_args__ = (
        # Composite FK back to findings' own composite PK (domain,
        # brand_id), on top of the plain brand_id -> brands FK below —
        # same pattern as FindingEvent/CrawledPage.
        ForeignKeyConstraint(
            ["domain", "brand_id"],
            ["findings.domain", "findings.brand_id"],
            name="fk_page_links_finding",
        ),
        UniqueConstraint(
            "domain",
            "brand_id",
            "from_url",
            "to_url",
            name="uq_page_links_domain_brand_edge",
        ),
        Index("ix_page_links_domain_brand", "domain", "brand_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    brand_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("brands.brand_id"))
    domain: Mapped[str] = mapped_column(String, nullable=False)
    from_url: Mapped[str] = mapped_column(String, nullable=False)
    to_url: Mapped[str] = mapped_column(String, nullable=False)
    is_external: Mapped[bool] = mapped_column(default=False)
    first_seen: Mapped[datetime] = mapped_column(
        UTCDateTime, server_default=func.now(), default=_utcnow
    )


class UsageEvent(Base):
    """Unused until usage-based billing (if ever) is switched on, but
    recorded from day one so that decision can be made from real
    historical data instead of a guess."""

    __tablename__ = "usage_events"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("tenants.tenant_id"), index=True
    )
    # "check_run" | "ct_query" | "domain_scanned"
    event_type: Mapped[str] = mapped_column(String, nullable=False)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    period: Mapped[str] = mapped_column(String, nullable=False)  # e.g. "2026-08"


class RateLimitState(Base):
    """Global, per-external-resource rate-limit suspension — global
    because a rate limit is a property of the resource (this worker's
    outbound IP hitting RDAP or crt.sh), not of any one brand or
    tenant; a 429 hit while checking one brand's candidates means every
    other brand's use of that same resource would hit it too. Persisted
    (not just an in-memory flag) so a suspension triggered by one
    worker invocation is honored by the next scheduled one — see
    worker/pipeline.py's RateLimiter."""

    __tablename__ = "rate_limit_state"

    resource: Mapped[str] = mapped_column(String, primary_key=True)  # "rdap" | "ct"
    suspended_until: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime, server_default=func.now(), default=_utcnow, onupdate=_utcnow
    )


class OnDemandScanRequest(Base):
    """One row per ad hoc "scan this domain right now" invocation — the
    on-demand counterpart to the daily worker's brand-driven scanning.
    This is *only* a job-tracking row: the actual result is a normal
    `Finding` (see worker/pipeline.py's `run_on_demand_scan`, tagged
    `source="on_demand"`), so it flows straight into the regular
    Findings UX — incident timeline, resolution workflow, CSV export,
    all of it — rather than a separate dossier/evidence view. This
    table exists only because the scan itself runs as a background
    task (see web/api/routes/on_demand_scans.py), so something needs a
    pollable status between "submitted" and "the Finding now exists."

    Brand-scoped, not tenant-scoped: `Finding`'s own PK is
    (domain, brand_id), so an on-demand scan needs a brand to attach
    its result to just like a generated or manually-added candidate
    does — the "on-demand" part is only about *when* the check runs
    (immediately, no daily cron wait), not about skipping the brand
    context those results normally live under.

    Each submission gets its own row (not upserted by domain), so
    re-scanning the same domain later keeps the earlier request as a
    free audit trail rather than overwriting it.
    """

    __tablename__ = "on_demand_scan_requests"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    brand_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("brands.brand_id"), index=True
    )
    domain: Mapped[str] = mapped_column(String, nullable=False)
    # "pending" (row created, background task not yet started) |
    # "running" | "completed" | "failed"
    status: Mapped[str] = mapped_column(String, nullable=False, default="pending")
    requested_at: Mapped[datetime] = mapped_column(
        UTCDateTime, server_default=func.now(), default=_utcnow
    )
    # Bumped on every status transition — used to detect a "running"
    # request whose process died mid-job (see worker/pipeline.py's
    # ON_DEMAND_SCAN_STALE_AFTER) rather than trusting it forever, the
    # same discard-don't-trust fix already applied to the daily
    # worker's own stale scan cursors.
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime, server_default=func.now(), default=_utcnow, onupdate=_utcnow
    )
    error: Mapped[str | None] = mapped_column(String, nullable=True)
