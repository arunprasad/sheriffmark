"""Ad hoc "scan this domain right now" requests — the sporadic-use
counterpart to a brand's ongoing generated/CT/custom-domain scanning.
A caller supplies one or a few domains it already suspects, not a
brand's watchlist to work through, and gets back a normal `Finding`
(source="on_demand") once the scan completes — there's no separate
evidence/dossier view here by design: "dossier is actually a result of
scan, which in turn a finding... on-demand is just invocation hooks,
results flow into regular ux flow." This router only tracks the
request's pending/running/completed/failed status; once "completed",
the result is already sitting in the normal findings list
(GET /api/findings?brand_id=...).

Kicked off immediately via FastAPI's BackgroundTasks (Starlette runs a
sync background function in a worker thread automatically, so this
doesn't block the request or the event loop) rather than the daily
worker's cron schedule — see worker/pipeline.py's `run_on_demand_scan`
docstring for why that's the right trade-off for how occasional this
usage is expected to be.
"""

import logging
import uuid
from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from adapters.storage_postgres import (
    complete_on_demand_scan_request,
    create_on_demand_scan_request,
    fail_on_demand_scan_request,
    get_on_demand_scan_request,
    list_on_demand_scan_requests,
    mark_on_demand_scan_running,
)
from shared.db import SessionLocal, get_session
from shared.domains import normalize_domain
from shared.models import Brand, OnDemandScanRequest, Tenant
from web.api.tenancy import get_current_tenant
from worker.pipeline import run_on_demand_scan

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/brands/{brand_id}/on-demand-scans", tags=["on-demand-scans"])

# A handful, not a batch job — this is the "few domains" ad hoc lookup,
# not a replacement for the brand's own generated-candidate scan.
# Keeps one submission from spinning up an unbounded number of
# concurrent background threads, each doing a real network check.
MAX_DOMAINS_PER_REQUEST = 5


class OnDemandScanCreateIn(BaseModel):
    domains: list[str]

    @field_validator("domains")
    @classmethod
    def validate_domains(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("at least one domain is required")
        if len(v) > MAX_DOMAINS_PER_REQUEST:
            raise ValueError(f"at most {MAX_DOMAINS_PER_REQUEST} domains per request")
        return [normalize_domain(d) for d in v]


class OnDemandScanRequestOut(BaseModel):
    id: uuid.UUID
    domain: str
    status: str
    requested_at: datetime
    updated_at: datetime
    error: str | None

    @classmethod
    def from_model(cls, request: OnDemandScanRequest) -> "OnDemandScanRequestOut":
        return cls(
            id=request.id,
            domain=request.domain,
            status=request.status,
            requested_at=request.requested_at,
            updated_at=request.updated_at,
            error=request.error,
        )


def _get_owned_brand(brand_id: uuid.UUID, tenant: Tenant, session: Session) -> Brand:
    """Same 404-not-403 ownership check as brands.py's own — a brand_id
    belonging to another tenant shouldn't reveal that it exists."""
    brand = session.get(Brand, brand_id)
    if brand is None or brand.tenant_id != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Brand not found")
    return brand


def _run_scan_job(brand_id: uuid.UUID, request_id: uuid.UUID) -> None:
    """The actual background job. Opens its own DB session — the
    request's session is already closed by the time a background task
    runs (FastAPI/Starlette execute these after the response is sent)."""
    session = SessionLocal()
    try:
        mark_on_demand_scan_running(session, request_id=request_id)
        request = session.get(OnDemandScanRequest, request_id)
        if request is None:
            return
        brand = session.get(Brand, brand_id)
        if brand is None:
            fail_on_demand_scan_request(
                session, request_id=request_id, error="Brand no longer exists"
            )
            return
        try:
            reg_status = run_on_demand_scan(session, brand, request.domain)
        except Exception as e:  # noqa: BLE001 - fail the request, don't crash the thread
            logger.exception("on-demand scan failed for %s", request.domain)
            fail_on_demand_scan_request(session, request_id=request_id, error=str(e))
            return

        if reg_status.rate_limited:
            fail_on_demand_scan_request(
                session,
                request_id=request_id,
                error="RDAP is currently rate-limited — try again shortly.",
            )
            return
        if reg_status.status == "unknown":
            fail_on_demand_scan_request(
                session,
                request_id=request_id,
                error="Couldn't determine this domain's registration status — try again.",
            )
            return
        complete_on_demand_scan_request(session, request_id=request_id)
    finally:
        session.close()


@router.post("", response_model=list[OnDemandScanRequestOut], status_code=202)
def create_on_demand_scans(
    brand_id: uuid.UUID,
    payload: OnDemandScanCreateIn,
    background_tasks: BackgroundTasks,
    tenant: Tenant = Depends(get_current_tenant),
    session: Session = Depends(get_session),
) -> list[OnDemandScanRequestOut]:
    _get_owned_brand(brand_id, tenant, session)

    requests = [
        create_on_demand_scan_request(session, brand_id=brand_id, domain=domain)
        for domain in payload.domains
    ]
    session.commit()
    for request in requests:
        session.refresh(request)
        background_tasks.add_task(_run_scan_job, brand_id, request.id)
    return [OnDemandScanRequestOut.from_model(r) for r in requests]


@router.get("", response_model=list[OnDemandScanRequestOut])
def list_on_demand_scans(
    brand_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    session: Session = Depends(get_session),
) -> list[OnDemandScanRequestOut]:
    _get_owned_brand(brand_id, tenant, session)
    requests = list_on_demand_scan_requests(session, brand_id=brand_id)
    return [OnDemandScanRequestOut.from_model(r) for r in requests]


@router.get("/{request_id}", response_model=OnDemandScanRequestOut)
def get_on_demand_scan(
    brand_id: uuid.UUID,
    request_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    session: Session = Depends(get_session),
) -> OnDemandScanRequestOut:
    _get_owned_brand(brand_id, tenant, session)
    request = get_on_demand_scan_request(session, brand_id=brand_id, request_id=request_id)
    if request is None:
        raise HTTPException(status_code=404, detail="Scan request not found")
    return OnDemandScanRequestOut.from_model(request)
