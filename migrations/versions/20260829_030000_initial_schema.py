"""initial schema: tenants, plans, brands, findings, and everything built
on top of them since

Revision ID: 20260829_030000
Revises:
Create Date: 2026-08-29

Squashed from the 16 incremental migrations this schema actually grew
through (2026-08-22 through 2026-08-29) into a single fresh baseline —
safe because this project has never had a real production deployment
(see several models.py docstrings making the same point). Reasons for
squashing now rather than later:

1. **SQLite as the new default store** (see shared/config.py) needs
   portable column types. The old migrations wrote
   `postgresql.ARRAY`/`postgresql.JSONB` directly — those don't compile
   against any other dialect, so they'd hard-fail the moment anyone ran
   `alembic upgrade head` against a fresh SQLite file. This baseline uses
   `sa.JSON().with_variant(postgresql.ARRAY(...)/JSONB(...), "postgresql")`
   instead (see shared/models.py's `StringList`/`JSONBlob`) — plain JSON
   on SQLite (and every other backend), the exact same native Postgres
   type as before wherever DATABASE_URL still points at Postgres. Zero
   schema change for any existing Postgres deployment. Every timestamp
   column is plain `sa.DateTime(timezone=True)` here rather than
   shared/models.py's `UTCDateTime` wrapper — the DDL/storage is
   identical either way (`UTCDateTime` only affects Python-side reads,
   not the column type on disk), and a migration deliberately doesn't
   import application code so it stays a frozen historical record even
   if that wrapper's implementation changes later.
2. Sixteen migrations for a schema still this young was already more
   history than signal — several were narrow additive column bolt-ons
   (e.g. one column apiece for abuse_email, owned_domains,
   ct_last_cert_id) that add nothing to understanding the current shape
   of the data by staying split out.

Every index, composite foreign key, and unique constraint here (e.g.
`crawled_pages`/`page_links`/`finding_events`' composite FK back to
`findings`' own composite PK) matches exactly what the old 16 migrations
had actually built, verified by stamping this revision onto the real,
already-migrated dev Postgres database and confirming `alembic check`
reports zero drift — these were originally added by hand via
`op.create_index`/`op.create_foreign_key`/`op.create_unique_constraint`
calls without a matching declaration in shared/models.py (plain
`ForeignKey(...)` doesn't imply an index), which autogenerate alone
would have silently dropped. They're now declared properly in
shared/models.py itself (`index=True`, `__table_args__`) so autogenerate
stays trustworthy from here on.

The one non-schema migration folded in here is `20260823_000000`'s data
change: the seeded `plans` row ships directly as "Self-Hosted"/unlimited
(no `max_brands` cap) rather than the original "Free"/capped row that
migration used to convert away from — this project made the OSS-pivot
call for good before any deployment existed to migrate.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "20260829_030000"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "local_credentials",
        sa.Column("external_id", sa.String(), nullable=False),
        sa.Column("email", sa.String(), nullable=False),
        sa.Column("password_hash", sa.String(), nullable=False),
        sa.Column("email_verified", sa.Boolean(), nullable=False),
        sa.Column("verification_token", sa.String(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("external_id"),
        sa.UniqueConstraint("email"),
    )
    op.create_table(
        "plans",
        sa.Column("plan_id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column(
            "limits",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("plan_id"),
    )
    op.create_table(
        "rate_limit_state",
        sa.Column("resource", sa.String(), nullable=False),
        sa.Column("suspended_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("resource"),
    )
    op.create_table(
        "signing_keys",
        sa.Column("kid", sa.String(), nullable=False),
        sa.Column("private_key_pem", sa.String(), nullable=False),
        sa.Column("public_key_pem", sa.String(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("kid"),
    )
    op.create_table(
        "tenants",
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("plan_id", sa.String(), nullable=False),
        sa.Column("stripe_customer_id", sa.String(), nullable=True),
        sa.Column("contact_email", sa.String(), nullable=True),
        sa.Column(
            "notification_channels",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["plan_id"], ["plans.plan_id"]),
        sa.PrimaryKeyConstraint("tenant_id"),
    )
    op.create_table(
        "brands",
        sa.Column("brand_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column(
            "keywords",
            sa.JSON().with_variant(postgresql.ARRAY(sa.String()), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "tlds",
            sa.JSON().with_variant(postgresql.ARRAY(sa.String()), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "variant_rules",
            sa.JSON().with_variant(postgresql.ARRAY(sa.String()), "postgresql"),
            nullable=False,
        ),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("ct_last_cert_id", sa.Integer(), nullable=True),
        sa.Column(
            "custom_domains",
            sa.JSON().with_variant(postgresql.ARRAY(sa.String()), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "owned_domains",
            sa.JSON().with_variant(postgresql.ARRAY(sa.String()), "postgresql"),
            nullable=False,
        ),
        sa.Column("generated_scan_cursor", sa.String(), nullable=True),
        sa.Column("custom_scan_cursor", sa.String(), nullable=True),
        sa.Column("generated_scan_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("custom_scan_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_scan_completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.tenant_id"]),
        sa.PrimaryKeyConstraint("brand_id"),
        sa.Index("ix_brands_tenant_id", "tenant_id"),
    )
    op.create_table(
        "usage_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("event_type", sa.String(), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False),
        sa.Column("period", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.tenant_id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.Index("ix_usage_events_tenant_id", "tenant_id"),
    )
    op.create_table(
        "users",
        sa.Column("external_id", sa.String(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("role", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.tenant_id"]),
        sa.PrimaryKeyConstraint("external_id"),
        sa.Index("ix_users_tenant_id", "tenant_id"),
    )
    op.create_table(
        "findings",
        sa.Column("domain", sa.String(), nullable=False),
        sa.Column("brand_id", sa.Uuid(), nullable=False),
        sa.Column("source", sa.String(), nullable=False),
        sa.Column(
            "first_seen", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "last_checked", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("registrar", sa.String(), nullable=True),
        sa.Column("created_date", sa.Date(), nullable=True),
        sa.Column("abuse_email", sa.String(), nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=True),
        sa.Column(
            "risk_factors",
            sa.JSON().with_variant(postgresql.ARRAY(sa.String()), "postgresql"),
            nullable=False,
        ),
        sa.Column("alerted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "dns_snapshot",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "website_snapshot",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=False,
        ),
        sa.Column("screenshot_data", sa.LargeBinary(), nullable=True),
        sa.Column("screenshot_content_type", sa.String(), nullable=True),
        sa.Column("screenshot_captured_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolution_status", sa.String(), nullable=False),
        sa.Column("resolution_note", sa.String(), nullable=True),
        sa.ForeignKeyConstraint(["brand_id"], ["brands.brand_id"]),
        sa.PrimaryKeyConstraint("domain", "brand_id"),
        sa.Index("ix_findings_brand_id", "brand_id"),
    )
    op.create_table(
        "on_demand_scan_requests",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("brand_id", sa.Uuid(), nullable=False),
        sa.Column("domain", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column(
            "requested_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("error", sa.String(), nullable=True),
        sa.ForeignKeyConstraint(["brand_id"], ["brands.brand_id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.Index("ix_on_demand_scan_requests_brand_id", "brand_id"),
    )
    op.create_table(
        "reference_images",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("brand_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("filename", sa.String(), nullable=True),
        sa.Column("content_type", sa.String(), nullable=False),
        sa.Column("image_data", sa.LargeBinary(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["brand_id"], ["brands.brand_id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.Index("ix_reference_images_brand_id", "brand_id"),
    )
    op.create_table(
        "crawled_pages",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("brand_id", sa.Uuid(), nullable=False),
        sa.Column("domain", sa.String(), nullable=False),
        sa.Column("url", sa.String(), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("content_hash", sa.String(), nullable=True),
        sa.Column("last_modified", sa.String(), nullable=True),
        sa.Column("etag", sa.String(), nullable=True),
        sa.Column("title", sa.String(), nullable=True),
        sa.Column("has_forms", sa.Boolean(), nullable=False),
        sa.Column("form_count", sa.Integer(), nullable=False),
        sa.Column("has_password_field", sa.Boolean(), nullable=False),
        sa.Column("is_spa", sa.Boolean(), nullable=False),
        sa.Column(
            "spa_signals",
            sa.JSON().with_variant(postgresql.ARRAY(sa.String()), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "first_seen", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "last_checked", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["brand_id"], ["brands.brand_id"]),
        # Composite FK back to findings' own composite PK (domain,
        # brand_id), on top of the plain brand_id -> brands FK above.
        sa.ForeignKeyConstraint(
            ["domain", "brand_id"],
            ["findings.domain", "findings.brand_id"],
            name="fk_crawled_pages_finding",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("domain", "brand_id", "url", name="uq_crawled_pages_domain_brand_url"),
        sa.Index("ix_crawled_pages_domain_brand", "domain", "brand_id"),
    )
    op.create_table(
        "finding_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("brand_id", sa.Uuid(), nullable=False),
        sa.Column("domain", sa.String(), nullable=False),
        sa.Column("event_type", sa.String(), nullable=False),
        sa.Column(
            "detected_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "details",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["brand_id"], ["brands.brand_id"]),
        sa.ForeignKeyConstraint(
            ["domain", "brand_id"],
            ["findings.domain", "findings.brand_id"],
            name="fk_finding_events_finding",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.Index("ix_finding_events_detected_at", "detected_at"),
        sa.Index("ix_finding_events_domain_brand", "domain", "brand_id"),
    )
    op.create_table(
        "page_links",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("brand_id", sa.Uuid(), nullable=False),
        sa.Column("domain", sa.String(), nullable=False),
        sa.Column("from_url", sa.String(), nullable=False),
        sa.Column("to_url", sa.String(), nullable=False),
        sa.Column("is_external", sa.Boolean(), nullable=False),
        sa.Column(
            "first_seen", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["brand_id"], ["brands.brand_id"]),
        sa.ForeignKeyConstraint(
            ["domain", "brand_id"],
            ["findings.domain", "findings.brand_id"],
            name="fk_page_links_finding",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "domain",
            "brand_id",
            "from_url",
            "to_url",
            name="uq_page_links_domain_brand_edge",
        ),
        sa.Index("ix_page_links_domain_brand", "domain", "brand_id"),
    )

    # Seed data — the one non-schema piece folded in from the old
    # migration history (see this module's docstring). Ships unlimited
    # from day one; `check_limit()` (shared/limits.py) treats a missing
    # `max_brands` key as unlimited.
    op.execute(
        "INSERT INTO plans (plan_id, name, limits) VALUES "
        "('free', 'Self-Hosted', '{\"ct_poll\": true, \"dashboard\": true}')"
    )


def downgrade() -> None:
    op.drop_table("page_links")
    op.drop_table("finding_events")
    op.drop_table("crawled_pages")
    op.drop_table("reference_images")
    op.drop_table("on_demand_scan_requests")
    op.drop_table("findings")
    op.drop_table("users")
    op.drop_table("usage_events")
    op.drop_table("brands")
    op.drop_table("tenants")
    op.drop_table("signing_keys")
    op.drop_table("rate_limit_state")
    op.drop_table("plans")
    op.drop_table("local_credentials")
