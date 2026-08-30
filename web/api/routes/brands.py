"""Brand CRUD — the tenant's watchlist configuration. Every endpoint is
scoped to the caller's own tenant via `get_current_tenant`; there is no
path here that can read or write another tenant's brands.
"""

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, field_validator
from sqlalchemy.orm import Session

from adapters.storage_postgres import (
    add_owned_domain,
    count_unresolved_findings,
    create_reference_image,
    delete_reference_image,
    get_reference_image,
    list_reference_images,
)
from shared.db import get_session
from shared.domains import normalize_domain
from shared.limits import check_limit
from shared.models import Brand, Tenant
from web.api.tenancy import get_current_tenant

router = APIRouter(prefix="/api/brands", tags=["brands"])

# Enough for a real logo/screenshot upload without letting one request
# put an unbounded blob in Postgres — reference_images.image_data is
# bytea, not object storage (see shared/models.py's ReferenceImage
# docstring for why that trade-off is fine at this volume).
MAX_REFERENCE_IMAGE_BYTES = 2_000_000
ALLOWED_REFERENCE_IMAGE_TYPES = {"image/png", "image/jpeg", "image/webp"}
ALLOWED_REFERENCE_IMAGE_KINDS = {"logo", "site_screenshot"}


class BrandIn(BaseModel):
    name: str
    keywords: list[str] = []
    tlds: list[str] = []


class BrandUpdateIn(BaseModel):
    """All fields optional — a plain partial update (PATCH semantics).
    `active` is the pause/resume control: `worker/pipeline.py`'s
    `process_tenant` already skips inactive brands entirely, so this
    endpoint is the only piece that was missing."""

    name: str | None = None
    keywords: list[str] | None = None
    tlds: list[str] | None = None
    active: bool | None = None


class BrandOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    brand_id: uuid.UUID
    name: str
    keywords: list[str]
    tlds: list[str]
    active: bool
    custom_domains: list[str]
    owned_domains: list[str]
    last_scan_completed_at: datetime | None
    # Not a real column — attached as a transient attribute by
    # list_brands (the only endpoint that bothers computing it; every
    # other endpoint here returns a Brand straight from the ORM, where
    # this just falls back to the default below rather than erroring).
    unresolved_findings_count: int = 0


class CustomDomainIn(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        return normalize_domain(v)


class OwnedDomainIn(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        return normalize_domain(v)


def _get_owned_brand(brand_id: uuid.UUID, tenant: Tenant, session: Session) -> Brand:
    """Shared ownership check — 404, not 403, so a brand_id belonging to
    another tenant doesn't reveal that it exists at all. Used by every
    endpoint below that operates on one specific brand."""
    brand = session.get(Brand, brand_id)
    if brand is None or brand.tenant_id != tenant.tenant_id:
        raise HTTPException(status_code=404, detail="Brand not found")
    return brand


@router.get("", response_model=list[BrandOut])
def list_brands(
    tenant: Tenant = Depends(get_current_tenant), session: Session = Depends(get_session)
) -> list[Brand]:
    brands = tenant.brands
    for brand in brands:
        # Transient, not persisted — see BrandOut's field comment.
        brand.unresolved_findings_count = count_unresolved_findings(
            session, brand_id=brand.brand_id
        )
    return brands


@router.post("", response_model=BrandOut, status_code=201)
def create_brand(
    payload: BrandIn,
    tenant: Tenant = Depends(get_current_tenant),
    session: Session = Depends(get_session),
) -> Brand:
    if not check_limit(tenant, "brand_create"):
        raise HTTPException(status_code=402, detail="Brand limit reached for your plan")

    brand = Brand(
        tenant_id=tenant.tenant_id,
        name=payload.name,
        keywords=payload.keywords,
        tlds=payload.tlds,
        variant_rules=[],
        custom_domains=[],
        owned_domains=[],
        active=True,
    )
    session.add(brand)
    session.commit()
    session.refresh(brand)
    return brand


@router.patch("/{brand_id}", response_model=BrandOut)
def update_brand(
    brand_id: uuid.UUID,
    payload: BrandUpdateIn,
    tenant: Tenant = Depends(get_current_tenant),
    session: Session = Depends(get_session),
) -> Brand:
    """Partial update — name/keywords/TLDs, and the pause/resume
    toggle. Previously the only way to change any of these was delete
    and recreate the brand, losing its findings/incident history."""
    brand = _get_owned_brand(brand_id, tenant, session)
    updates = payload.model_dump(exclude_unset=True)
    for field, value in updates.items():
        setattr(brand, field, value)
    if updates:
        session.commit()
        session.refresh(brand)
    return brand


@router.delete("/{brand_id}", status_code=204)
def delete_brand(
    brand_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    session: Session = Depends(get_session),
) -> None:
    brand = _get_owned_brand(brand_id, tenant, session)
    session.delete(brand)
    session.commit()


@router.post("/{brand_id}/custom-domains", response_model=BrandOut, status_code=201)
def add_custom_domain(
    brand_id: uuid.UUID,
    payload: CustomDomainIn,
    tenant: Tenant = Depends(get_current_tenant),
    session: Session = Depends(get_session),
) -> Brand:
    """Manual watchlist: add one exact domain to a brand's monitoring,
    for when dnstwist's algorithmic generation missed something a user
    was specifically worried about. Checked by the worker the same way
    as generated candidates — see worker/pipeline.py's
    process_brand_custom.
    """
    brand = _get_owned_brand(brand_id, tenant, session)
    if payload.domain not in brand.custom_domains:
        # Reassign (not .append) — SQLAlchemy only detects ARRAY column
        # mutation via a new list object, not in-place mutation of the
        # existing one.
        brand.custom_domains = [*brand.custom_domains, payload.domain]
        session.commit()
        session.refresh(brand)
    return brand


@router.delete("/{brand_id}/custom-domains/{domain}", response_model=BrandOut)
def remove_custom_domain(
    brand_id: uuid.UUID,
    domain: str,
    tenant: Tenant = Depends(get_current_tenant),
    session: Session = Depends(get_session),
) -> Brand:
    brand = _get_owned_brand(brand_id, tenant, session)
    normalized = domain.strip().lower()
    if normalized in brand.custom_domains:
        brand.custom_domains = [d for d in brand.custom_domains if d != normalized]
        session.commit()
        session.refresh(brand)
    return brand


@router.post("/{brand_id}/owned-domains", response_model=BrandOut, status_code=201)
def create_owned_domain(
    brand_id: uuid.UUID,
    payload: OwnedDomainIn,
    tenant: Tenant = Depends(get_current_tenant),
    session: Session = Depends(get_session),
) -> Brand:
    """Declare a domain the tenant already legitimately owns (a
    defensive registration, a secondary brand domain). Opposite purpose
    from custom-domains: seeds typosquat generation too (a squat of an
    owned domain is worth catching), but is filtered out of every
    detection path's results — see worker/pipeline.py's
    process_brand_generated. Also removed from custom_domains if
    present there, since watching your own domain as a squat candidate
    is a contradiction worth resolving rather than leaving in place.
    """
    brand = _get_owned_brand(brand_id, tenant, session)
    if add_owned_domain(session, brand=brand, domain=payload.domain):
        session.commit()
        session.refresh(brand)
    return brand


@router.delete("/{brand_id}/owned-domains/{domain}", response_model=BrandOut)
def remove_owned_domain(
    brand_id: uuid.UUID,
    domain: str,
    tenant: Tenant = Depends(get_current_tenant),
    session: Session = Depends(get_session),
) -> Brand:
    brand = _get_owned_brand(brand_id, tenant, session)
    normalized = domain.strip().lower()
    if normalized in brand.owned_domains:
        brand.owned_domains = [d for d in brand.owned_domains if d != normalized]
        session.commit()
        session.refresh(brand)
    return brand


class ReferenceImageOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    kind: str
    filename: str | None
    content_type: str
    created_at: datetime


@router.post(
    "/{brand_id}/reference-images", response_model=ReferenceImageOut, status_code=201
)
async def upload_reference_image(
    brand_id: uuid.UUID,
    kind: str = Form(...),
    file: UploadFile = File(...),
    tenant: Tenant = Depends(get_current_tenant),
    session: Session = Depends(get_session),
) -> ReferenceImageOut:
    """Upload a brand logo or a screenshot of the real site — the
    comparison target for visual similarity detection
    (core/visual_similarity.py), checked against every screenshot
    captured for this brand's findings (worker/pipeline.py)."""
    _get_owned_brand(brand_id, tenant, session)

    if kind not in ALLOWED_REFERENCE_IMAGE_KINDS:
        raise HTTPException(
            status_code=422,
            detail=f"kind must be one of {sorted(ALLOWED_REFERENCE_IMAGE_KINDS)}",
        )
    if file.content_type not in ALLOWED_REFERENCE_IMAGE_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"content type must be one of {sorted(ALLOWED_REFERENCE_IMAGE_TYPES)}",
        )

    data = await file.read(MAX_REFERENCE_IMAGE_BYTES + 1)
    if len(data) > MAX_REFERENCE_IMAGE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Image exceeds the {MAX_REFERENCE_IMAGE_BYTES // 1_000_000}MB limit",
        )
    if not data:
        raise HTTPException(status_code=422, detail="Uploaded file is empty")

    image = create_reference_image(
        session,
        brand_id=brand_id,
        kind=kind,
        content_type=file.content_type,
        image_data=data,
        filename=file.filename,
    )
    return image


@router.get("/{brand_id}/reference-images", response_model=list[ReferenceImageOut])
def list_brand_reference_images(
    brand_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    session: Session = Depends(get_session),
) -> list[ReferenceImageOut]:
    _get_owned_brand(brand_id, tenant, session)
    return list_reference_images(session, brand_id=brand_id)


@router.get("/{brand_id}/reference-images/{image_id}")
def get_brand_reference_image(
    brand_id: uuid.UUID,
    image_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    session: Session = Depends(get_session),
) -> Response:
    _get_owned_brand(brand_id, tenant, session)
    image = get_reference_image(session, brand_id=brand_id, image_id=image_id)
    if image is None:
        raise HTTPException(status_code=404, detail="Reference image not found")
    return Response(content=image.image_data, media_type=image.content_type)


@router.delete("/{brand_id}/reference-images/{image_id}", status_code=204)
def delete_brand_reference_image(
    brand_id: uuid.UUID,
    image_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    session: Session = Depends(get_session),
) -> None:
    _get_owned_brand(brand_id, tenant, session)
    if not delete_reference_image(session, brand_id=brand_id, image_id=image_id):
        raise HTTPException(status_code=404, detail="Reference image not found")
