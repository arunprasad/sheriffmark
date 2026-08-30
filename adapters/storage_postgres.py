"""Thin repository over the SQLAlchemy models — the only place
`worker/pipeline.py` touches the DB directly, so orchestration logic
stays readable and swappable independent of query details.
"""

import uuid
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from shared.models import (
    Brand,
    CrawledPage,
    Finding,
    FindingEvent,
    OnDemandScanRequest,
    PageLink,
    ReferenceImage,
    Tenant,
)


def get_active_tenants(session: Session) -> list[Tenant]:
    """All tenants with at least one active brand, brands eager-loaded so
    the pipeline doesn't N+1 per tenant."""
    stmt = (
        select(Tenant)
        .join(Brand)
        .where(Brand.active.is_(True))
        .options(selectinload(Tenant.brands))
        .distinct()
    )
    return list(session.execute(stmt).scalars().all())


def upsert_finding(
    session: Session,
    *,
    brand_id,
    domain: str,
    source: str,
    status: str,
    registrar: str | None = None,
    created_date: date | None = None,
    abuse_email: str | None = None,
    risk_score: int | None = None,
    risk_factors: list[str] | None = None,
    dns_snapshot: dict | None = None,
    website_snapshot: dict | None = None,
    screenshot_data: bytes | None = None,
    screenshot_content_type: str | None = None,
) -> tuple[Finding, bool]:
    """Insert or update a finding, keyed by (brand_id, domain). Returns
    (finding, is_new) — `is_new` is what the pipeline uses to decide what
    goes in the digest, so a finding that's just being re-confirmed on a
    later run doesn't get re-alerted every day.

    `dns_snapshot`/`website_snapshot` default to `None` (meaning "not
    acquired this run" — e.g. the candidate turned out unregistered, so
    there's nothing to crawl) and are left as an empty dict on first
    insert, unchanged on update, rather than overwriting a real prior
    snapshot with nothing.

    Same principle for `registrar`/`created_date`/`abuse_email`: a
    source that doesn't have this info (the CT path only knows a
    domain exists from a cert, not its RDAP record) passes `None`,
    which must not blank out real data a different source (RDAP, via
    the generated path) previously found for the same finding — found
    while building WHOIS-change detection (`worker/pipeline.py`),
    which depends on registrar continuity across runs to mean
    anything.
    """
    existing = session.get(Finding, {"domain": domain, "brand_id": brand_id})
    now = datetime.now()

    if existing is not None:
        existing.last_checked = now
        existing.status = status
        if registrar is not None:
            existing.registrar = registrar
        if created_date is not None:
            existing.created_date = created_date
        if abuse_email is not None:
            existing.abuse_email = abuse_email
        existing.risk_score = risk_score
        existing.risk_factors = risk_factors or []
        if dns_snapshot is not None:
            existing.dns_snapshot = dns_snapshot
        if website_snapshot is not None:
            existing.website_snapshot = website_snapshot
        if screenshot_data is not None:
            existing.screenshot_data = screenshot_data
            existing.screenshot_content_type = screenshot_content_type
            existing.screenshot_captured_at = now
        return existing, False

    finding = Finding(
        domain=domain,
        brand_id=brand_id,
        source=source,
        first_seen=now,
        last_checked=now,
        status=status,
        registrar=registrar,
        created_date=created_date,
        abuse_email=abuse_email,
        risk_score=risk_score,
        risk_factors=risk_factors or [],
        dns_snapshot=dns_snapshot or {},
        website_snapshot=website_snapshot or {},
        screenshot_data=screenshot_data,
        screenshot_content_type=screenshot_content_type,
        screenshot_captured_at=now if screenshot_data is not None else None,
    )
    session.add(finding)
    return finding, True


def create_finding_event(
    session: Session, *, brand_id, domain: str, event_type: str, details: dict
) -> FindingEvent:
    """Records one incident on a finding's timeline. Always a plain
    insert — events are immutable history, never updated in place."""
    event = FindingEvent(
        id=uuid.uuid4(),
        brand_id=brand_id,
        domain=domain,
        event_type=event_type,
        details=details,
    )
    session.add(event)
    return event


def list_finding_events(session: Session, *, brand_id, domain: str) -> list[FindingEvent]:
    stmt = (
        select(FindingEvent)
        .where(FindingEvent.brand_id == brand_id, FindingEvent.domain == domain)
        .order_by(FindingEvent.detected_at.desc())
    )
    return list(session.execute(stmt).scalars().all())


def sync_site_graph(
    session: Session, *, brand_id, domain: str, pages: list[dict], links: list[dict]
) -> None:
    """Upserts one crawl's worth of pages/edges (core/site_graph.py's
    output, already converted to plain dicts by the caller — see
    worker/pipeline.py). Pages are updated in place (a URL's content
    legitimately changes crawl to crawl); links are insert-if-new only,
    since an edge either exists or it doesn't — there's no "changed"
    state for a link to track."""
    for page in pages:
        existing = session.execute(
            select(CrawledPage).where(
                CrawledPage.brand_id == brand_id,
                CrawledPage.domain == domain,
                CrawledPage.url == page["url"],
            )
        ).scalar_one_or_none()
        if existing is None:
            session.add(
                CrawledPage(
                    brand_id=brand_id,
                    domain=domain,
                    url=page["url"],
                    status_code=page.get("status_code"),
                    content_hash=page.get("content_hash"),
                    last_modified=page.get("last_modified"),
                    etag=page.get("etag"),
                    title=page.get("title"),
                    has_forms=page.get("has_forms", False),
                    form_count=page.get("form_count", 0),
                    has_password_field=page.get("has_password_field", False),
                    is_spa=page.get("is_spa", False),
                    spa_signals=page.get("spa_signals", []),
                )
            )
        else:
            existing.status_code = page.get("status_code")
            existing.content_hash = page.get("content_hash")
            existing.last_modified = page.get("last_modified")
            existing.etag = page.get("etag")
            existing.title = page.get("title")
            existing.has_forms = page.get("has_forms", False)
            existing.form_count = page.get("form_count", 0)
            existing.has_password_field = page.get("has_password_field", False)
            existing.is_spa = page.get("is_spa", False)
            existing.spa_signals = page.get("spa_signals", [])
            existing.last_checked = func.now()

    for link in links:
        existing_link = session.execute(
            select(PageLink).where(
                PageLink.brand_id == brand_id,
                PageLink.domain == domain,
                PageLink.from_url == link["from_url"],
                PageLink.to_url == link["to_url"],
            )
        ).scalar_one_or_none()
        if existing_link is None:
            session.add(
                PageLink(
                    brand_id=brand_id,
                    domain=domain,
                    from_url=link["from_url"],
                    to_url=link["to_url"],
                    is_external=link.get("is_external", False),
                )
            )


def list_site_graph(
    session: Session, *, brand_id, domain: str
) -> tuple[list[CrawledPage], list[PageLink]]:
    pages = list(
        session.execute(
            select(CrawledPage)
            .where(CrawledPage.brand_id == brand_id, CrawledPage.domain == domain)
            .order_by(CrawledPage.url)
        )
        .scalars()
        .all()
    )
    links = list(
        session.execute(
            select(PageLink).where(PageLink.brand_id == brand_id, PageLink.domain == domain)
        )
        .scalars()
        .all()
    )
    return pages, links


def create_reference_image(
    session: Session,
    *,
    brand_id,
    kind: str,
    content_type: str,
    image_data: bytes,
    filename: str | None = None,
) -> ReferenceImage:
    image = ReferenceImage(
        brand_id=brand_id,
        kind=kind,
        filename=filename,
        content_type=content_type,
        image_data=image_data,
    )
    session.add(image)
    session.commit()
    session.refresh(image)
    return image


def list_reference_images(session: Session, *, brand_id) -> list[ReferenceImage]:
    stmt = select(ReferenceImage).where(ReferenceImage.brand_id == brand_id).order_by(
        ReferenceImage.created_at
    )
    return list(session.execute(stmt).scalars().all())


def get_reference_image(session: Session, *, brand_id, image_id) -> ReferenceImage | None:
    image = session.get(ReferenceImage, image_id)
    if image is None or image.brand_id != brand_id:
        return None
    return image


def delete_reference_image(session: Session, *, brand_id, image_id) -> bool:
    image = get_reference_image(session, brand_id=brand_id, image_id=image_id)
    if image is None:
        return False
    session.delete(image)
    session.commit()
    return True


def add_owned_domain(session: Session, *, brand: Brand, domain: str) -> bool:
    """Shared by the direct owned-domains API
    (web/api/routes/brands.py) and the findings "claim as owned"
    resolution action (web/api/routes/findings.py) — one place for the
    actual mutation (and its custom_domains cross-removal) so both
    callers behave identically. Returns whether anything changed, so a
    caller can skip an unnecessary commit."""
    changed = False
    if domain not in brand.owned_domains:
        brand.owned_domains = [*brand.owned_domains, domain]
        changed = True
    if domain in brand.custom_domains:
        brand.custom_domains = [d for d in brand.custom_domains if d != domain]
        changed = True
    return changed


def count_unresolved_findings(session: Session, *, brand_id) -> int:
    """"Unresolved" = a live registered finding without a closed-out
    resolution — "resolution_failed" still counts as unresolved
    (a resolution was attempted, the threat didn't go away), only
    "resolved"/"resolved_owned" don't."""
    stmt = select(func.count()).select_from(Finding).where(
        Finding.brand_id == brand_id,
        Finding.status == "registered",
        Finding.resolution_status.in_(["open", "resolution_failed"]),
    )
    return session.execute(stmt).scalar_one()


def set_finding_resolution(
    session: Session,
    *,
    brand_id,
    domain: str,
    resolution_status: str,
    note: str | None,
) -> Finding | None:
    """Records a resolution-workflow transition and its FindingEvent in
    one place, so the event type always matches the status change that
    produced it. Returns None if the finding doesn't exist (caller
    turns that into a 404) rather than raising."""
    finding = session.get(Finding, {"domain": domain, "brand_id": brand_id})
    if finding is None:
        return None
    finding.resolution_status = resolution_status
    finding.resolution_note = note
    # "open" reads as a state, not an action — the timeline entry for
    # transitioning back to it is a "reopened" event, same event-type-
    # names-an-action convention every other incident type here follows.
    event_type = "reopened" if resolution_status == "open" else resolution_status
    create_finding_event(
        session,
        brand_id=brand_id,
        domain=domain,
        event_type=event_type,
        details={"note": note} if note else {},
    )
    session.commit()
    return finding


def update_ct_cursor(session: Session, brand: Brand, max_cert_id: int) -> None:
    brand.ct_last_cert_id = max_cert_id


# A "pending"/"running" on-demand scan request older than this almost
# certainly means the process that was supposed to run it died
# mid-job — there's no scheduled retry to eventually pick it back up
# the way the daily worker's cursor would. Generous relative to
# run_on_demand_scan's own worst case (crawl_website + a browser
# render fallback + a screenshot capture, well under a minute in
# practice).
ON_DEMAND_SCAN_STALE_AFTER = timedelta(minutes=10)


def create_on_demand_scan_request(
    session: Session, *, brand_id: uuid.UUID, domain: str
) -> OnDemandScanRequest:
    request = OnDemandScanRequest(brand_id=brand_id, domain=domain, status="pending")
    session.add(request)
    return request


def list_on_demand_scan_requests(
    session: Session, *, brand_id: uuid.UUID
) -> list[OnDemandScanRequest]:
    stmt = (
        select(OnDemandScanRequest)
        .where(OnDemandScanRequest.brand_id == brand_id)
        .order_by(OnDemandScanRequest.requested_at.desc())
    )
    return list(session.execute(stmt).scalars().all())


def _discard_if_stale(request: OnDemandScanRequest) -> None:
    """Mutates the request in place (caller commits) rather than
    trusting a stuck "running" status forever — same discard-don't-
    trust-it philosophy already applied to the worker's own stale scan
    cursors (see worker/pipeline.py's _is_scan_stale)."""
    if request.status not in ("pending", "running"):
        return
    age = datetime.now(UTC) - request.updated_at
    if age > ON_DEMAND_SCAN_STALE_AFTER:
        request.status = "failed"
        request.error = "Timed out — the process handling this request may have restarted."


def get_on_demand_scan_request(
    session: Session, *, brand_id: uuid.UUID, request_id: uuid.UUID
) -> OnDemandScanRequest | None:
    request = session.get(OnDemandScanRequest, request_id)
    if request is None or request.brand_id != brand_id:
        return None
    _discard_if_stale(request)
    session.commit()
    return request


def mark_on_demand_scan_running(session: Session, *, request_id: uuid.UUID) -> None:
    request = session.get(OnDemandScanRequest, request_id)
    if request is None:
        return
    request.status = "running"
    session.commit()


def complete_on_demand_scan_request(session: Session, *, request_id: uuid.UUID) -> None:
    """Marks the job done — the actual result lives on the `Finding`
    `run_on_demand_scan` wrote via `_record_finding`, not here."""
    request = session.get(OnDemandScanRequest, request_id)
    if request is None:
        return
    request.status = "completed"
    session.commit()


def fail_on_demand_scan_request(session: Session, *, request_id: uuid.UUID, error: str) -> None:
    request = session.get(OnDemandScanRequest, request_id)
    if request is None:
        return
    request.status = "failed"
    request.error = error
    session.commit()
