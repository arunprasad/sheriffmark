"""Findings — read-only from the web app; the worker is the only writer.
Same tenant-scoping discipline as brands: a caller can only ever see
findings belonging to brands their own tenant owns.
"""

import csv
import io
import uuid
from datetime import date, datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, ConfigDict, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from adapters.storage_postgres import (
    add_owned_domain,
    list_finding_events,
    list_site_graph,
    set_finding_resolution,
)
from core.pdf_report import (
    FindingReportData,
    IncidentEntry,
    build_finding_report,
    describe_incident,
)
from shared.db import get_session
from shared.models import Finding, FindingEvent, Tenant
from web.api.tenancy import get_current_tenant

router = APIRouter(prefix="/api/findings", tags=["findings"])

# "resolution_failed" still counts as unresolved (see
# adapters.storage_postgres.count_unresolved_findings) — a resolution
# was attempted, the threat didn't go away.
_VALID_RESOLUTION_STATUSES = ("open", "resolved", "resolved_owned", "resolution_failed")


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    domain: str
    brand_id: uuid.UUID
    source: str
    status: str
    registrar: str | None
    created_date: date | None
    abuse_email: str | None
    risk_score: int | None
    risk_factors: list[str]
    first_seen: datetime
    last_checked: datetime
    resolution_status: str
    resolution_note: str | None


def _query_findings(
    tenant: Tenant,
    session: Session,
    brand_id: uuid.UUID | None,
    status: str | None = None,
    resolution_status: str | None = None,
) -> list[Finding]:
    """Shared tenant-scoping logic behind both the JSON and CSV export
    endpoints — this is the security-critical part (never let a caller
    see another tenant's findings), so it exists in exactly one place."""
    tenant_brand_ids = {b.brand_id for b in tenant.brands}

    if brand_id is not None:
        if brand_id not in tenant_brand_ids:
            raise HTTPException(status_code=404, detail="Brand not found")
        stmt = select(Finding).where(Finding.brand_id == brand_id)
    else:
        if not tenant_brand_ids:
            return []
        stmt = select(Finding).where(Finding.brand_id.in_(tenant_brand_ids))

    if status is not None:
        stmt = stmt.where(Finding.status == status)
    if resolution_status is not None:
        stmt = stmt.where(Finding.resolution_status == resolution_status)

    stmt = stmt.order_by(Finding.risk_score.desc().nulls_last(), Finding.first_seen.desc())
    return list(session.execute(stmt).scalars().all())


@router.get("", response_model=list[FindingOut])
def list_findings(
    brand_id: uuid.UUID | None = None,
    status: str | None = None,
    resolution_status: str | None = None,
    tenant: Tenant = Depends(get_current_tenant),
    session: Session = Depends(get_session),
) -> list[Finding]:
    """`status` filters the DNS/RDAP registration state (e.g.
    `status=registered` for the console's "flagged only" Findings
    view); `resolution_status` filters the separate manual-workflow
    state (open/resolved/resolved_owned/resolution_failed)."""
    return _query_findings(tenant, session, brand_id, status, resolution_status)


@router.get("/export.csv")
def export_findings_csv(
    brand_id: uuid.UUID | None = None,
    tenant: Tenant = Depends(get_current_tenant),
    session: Session = Depends(get_session),
) -> StreamingResponse:
    """CSV export. Same tenant-scoping as the JSON endpoint (via
    `_query_findings`), so there's no separate access-control path to
    get wrong."""
    findings = _query_findings(tenant, session, brand_id)

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "domain",
            "brand_id",
            "source",
            "status",
            "registrar",
            "created_date",
            "abuse_email",
            "risk_score",
            "risk_factors",
            "first_seen",
            "last_checked",
        ]
    )
    for f in findings:
        writer.writerow(
            [
                f.domain,
                f.brand_id,
                f.source,
                f.status,
                f.registrar or "",
                f.created_date.isoformat() if f.created_date else "",
                f.abuse_email or "",
                f.risk_score if f.risk_score is not None else "",
                ";".join(f.risk_factors),
                f.first_seen.isoformat(),
                f.last_checked.isoformat(),
            ]
        )
    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=findings.csv"},
    )


class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    event_type: str
    detected_at: datetime
    details: dict


@router.get("/{domain}/incidents", response_model=list[IncidentOut])
def list_finding_incidents(
    domain: str,
    brand_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    session: Session = Depends(get_session),
) -> list[FindingEvent]:
    """Incident timeline for one specific finding — the dashboard
    drill-down behind a finding's history. `brand_id` is required, not
    optional: a domain string alone isn't tenant-scoped, `Finding`'s own
    PK is (domain, brand_id)."""
    tenant_brand_ids = {b.brand_id for b in tenant.brands}
    if brand_id not in tenant_brand_ids:
        raise HTTPException(status_code=404, detail="Brand not found")
    return list_finding_events(session, brand_id=brand_id, domain=domain)


class CrawledPageOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    url: str
    status_code: int | None
    content_hash: str | None
    last_modified: str | None
    etag: str | None
    title: str | None
    has_forms: bool
    form_count: int
    has_password_field: bool
    is_spa: bool
    spa_signals: list[str]
    first_seen: datetime
    last_checked: datetime


class PageLinkOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    from_url: str
    to_url: str
    is_external: bool


class SiteGraphOut(BaseModel):
    pages: list[CrawledPageOut]
    links: list[PageLinkOut]


@router.get("/{domain}/site-graph", response_model=SiteGraphOut)
def get_finding_site_graph(
    domain: str,
    brand_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    session: Session = Depends(get_session),
) -> SiteGraphOut:
    """The crawled page graph for one finding (core/site_spider.py) —
    same tenant-scoping and (domain, brand_id) requirement as the
    incidents endpoint above."""
    tenant_brand_ids = {b.brand_id for b in tenant.brands}
    if brand_id not in tenant_brand_ids:
        raise HTTPException(status_code=404, detail="Brand not found")
    pages, links = list_site_graph(session, brand_id=brand_id, domain=domain)
    return SiteGraphOut(pages=pages, links=links)


@router.get("/{domain}/screenshot")
def get_finding_screenshot(
    domain: str,
    brand_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    session: Session = Depends(get_session),
) -> Response:
    """The screenshot captured for this finding (core/screenshot.py),
    if one exists — captured on first registration or when
    website_snapshot.content_hash changes, not every scan. 404 if the
    finding doesn't exist, isn't owned by the caller's tenant, or no
    screenshot has been captured yet (e.g. Playwright isn't installed
    on this deployment, or the domain hasn't been checked since this
    feature shipped)."""
    tenant_brand_ids = {b.brand_id for b in tenant.brands}
    if brand_id not in tenant_brand_ids:
        raise HTTPException(status_code=404, detail="Brand not found")

    finding = session.get(Finding, {"domain": domain, "brand_id": brand_id})
    if finding is None or finding.screenshot_data is None:
        raise HTTPException(status_code=404, detail="No screenshot captured for this finding")
    return Response(
        content=finding.screenshot_data,
        media_type=finding.screenshot_content_type or "image/png",
    )


@router.get("/{domain}/report.pdf")
def get_finding_report(
    domain: str,
    brand_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    session: Session = Depends(get_session),
) -> Response:
    """The evidence dossier. Assembles everything already acquired about
    this one finding (registration, DNS, blocklist hits, the website
    snapshot, the screenshot, the full incident timeline) into a single
    PDF via core/pdf_report.py.
    Recording only, same as the abuse-contact/blocklist enrichments
    this pulls from — this hands a human a document, it doesn't draft
    or send anything itself."""
    tenant_brands = {b.brand_id: b for b in tenant.brands}
    brand = tenant_brands.get(brand_id)
    if brand is None:
        raise HTTPException(status_code=404, detail="Brand not found")

    finding = session.get(Finding, {"domain": domain, "brand_id": brand_id})
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    events = list_finding_events(session, brand_id=brand_id, domain=domain)
    report = FindingReportData(
        domain=finding.domain,
        brand_name=brand.name,
        source=finding.source,
        status=finding.status,
        registrar=finding.registrar,
        created_date=finding.created_date,
        abuse_email=finding.abuse_email,
        risk_score=finding.risk_score,
        risk_factors=finding.risk_factors,
        resolution_status=finding.resolution_status,
        resolution_note=finding.resolution_note,
        first_seen=finding.first_seen,
        last_checked=finding.last_checked,
        dns_snapshot=finding.dns_snapshot or {},
        website_snapshot=finding.website_snapshot or {},
        screenshot_data=finding.screenshot_data,
        incidents=[
            IncidentEntry(
                event_type=e.event_type,
                detected_at=e.detected_at,
                description=describe_incident(e.event_type, e.details),
            )
            for e in events
        ],
    )
    pdf_bytes = build_finding_report(report)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={domain}-report.pdf"},
    )


class ResolutionIn(BaseModel):
    status: str
    note: str | None = None

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        if v not in _VALID_RESOLUTION_STATUSES:
            raise ValueError(f"status must be one of {_VALID_RESOLUTION_STATUSES}")
        return v


@router.post("/{domain}/resolution", response_model=FindingOut)
def resolve_finding(
    domain: str,
    brand_id: uuid.UUID,
    payload: ResolutionIn,
    tenant: Tenant = Depends(get_current_tenant),
    session: Session = Depends(get_session),
) -> Finding:
    """Records a resolution-workflow transition. `status="resolved_owned"`
    is a composite action — it also adds `domain` to the brand's
    `owned_domains` (see `add_owned_domain`), which is what actually
    stops it from being re-flagged by future scans; the resolution
    status alone would only affect this one finding's display, not the
    detection pipeline. Every transition (including reopening back to
    "open") gets its own `FindingEvent`, so the incident timeline stays
    the record of *when* and *why*, not just the current state."""
    tenant_brands = {b.brand_id: b for b in tenant.brands}
    brand = tenant_brands.get(brand_id)
    if brand is None:
        raise HTTPException(status_code=404, detail="Brand not found")

    if payload.status == "resolved_owned" and add_owned_domain(
        session, brand=brand, domain=domain
    ):
        session.commit()

    finding = set_finding_resolution(
        session,
        brand_id=brand_id,
        domain=domain,
        resolution_status=payload.status,
        note=payload.note,
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding
