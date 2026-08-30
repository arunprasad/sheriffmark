import uuid

import pytest

from adapters.storage_postgres import (
    create_reference_image,
    delete_reference_image,
    get_reference_image,
    list_reference_images,
)
from shared.db import SessionLocal
from shared.models import Brand, ReferenceImage, Tenant


@pytest.fixture
def session():
    s = SessionLocal()
    yield s
    s.rollback()
    s.close()


@pytest.fixture
def tenant_and_brand(session):
    tenant = Tenant(name=f"Test Tenant {uuid.uuid4()}", plan_id="free")
    session.add(tenant)
    session.flush()
    brand = Brand(
        tenant_id=tenant.tenant_id, name="testbrand", keywords=[], tlds=["com"], variant_rules=[]
    )
    session.add(brand)
    session.flush()
    session.commit()
    yield tenant, brand
    session.query(ReferenceImage).filter_by(brand_id=brand.brand_id).delete()
    session.query(Brand).filter_by(brand_id=brand.brand_id).delete()
    session.query(Tenant).filter_by(tenant_id=tenant.tenant_id).delete()
    session.commit()


class TestCreateAndListReferenceImages:
    def test_created_image_appears_in_the_list(self, session, tenant_and_brand):
        _, brand = tenant_and_brand

        image = create_reference_image(
            session,
            brand_id=brand.brand_id,
            kind="logo",
            content_type="image/png",
            image_data=b"fake-bytes",
            filename="logo.png",
        )

        images = list_reference_images(session, brand_id=brand.brand_id)

        assert len(images) == 1
        assert images[0].id == image.id
        assert images[0].kind == "logo"
        assert images[0].filename == "logo.png"

    def test_list_is_scoped_to_the_brand(self, session, tenant_and_brand):
        _, brand_a = tenant_and_brand
        other_tenant = Tenant(name=f"other-{uuid.uuid4()}", plan_id="free")
        session.add(other_tenant)
        session.flush()
        brand_b = Brand(
            tenant_id=other_tenant.tenant_id,
            name="otherbrand",
            keywords=[],
            tlds=["com"],
            variant_rules=[],
        )
        session.add(brand_b)
        session.flush()
        session.commit()

        try:
            create_reference_image(
                session,
                brand_id=brand_a.brand_id,
                kind="logo",
                content_type="image/png",
                image_data=b"a",
            )
            create_reference_image(
                session,
                brand_id=brand_b.brand_id,
                kind="logo",
                content_type="image/png",
                image_data=b"b",
            )

            assert len(list_reference_images(session, brand_id=brand_a.brand_id)) == 1
            assert len(list_reference_images(session, brand_id=brand_b.brand_id)) == 1
        finally:
            session.query(ReferenceImage).filter_by(brand_id=brand_b.brand_id).delete()
            session.query(Brand).filter_by(brand_id=brand_b.brand_id).delete()
            session.query(Tenant).filter_by(tenant_id=other_tenant.tenant_id).delete()
            session.commit()


class TestGetReferenceImage:
    def test_returns_the_image_for_the_owning_brand(self, session, tenant_and_brand):
        _, brand = tenant_and_brand
        image = create_reference_image(
            session,
            brand_id=brand.brand_id,
            kind="site_screenshot",
            content_type="image/png",
            image_data=b"fake-bytes",
        )

        result = get_reference_image(session, brand_id=brand.brand_id, image_id=image.id)

        assert result is not None
        assert result.image_data == b"fake-bytes"

    def test_returns_none_for_a_different_brand(self, session, tenant_and_brand):
        _, brand = tenant_and_brand
        image = create_reference_image(
            session, brand_id=brand.brand_id, kind="logo", content_type="image/png", image_data=b"a"
        )

        result = get_reference_image(session, brand_id=uuid.uuid4(), image_id=image.id)

        assert result is None

    def test_returns_none_for_an_unknown_id(self, session, tenant_and_brand):
        _, brand = tenant_and_brand

        result = get_reference_image(session, brand_id=brand.brand_id, image_id=uuid.uuid4())

        assert result is None


class TestDeleteReferenceImage:
    def test_deletes_and_returns_true(self, session, tenant_and_brand):
        _, brand = tenant_and_brand
        image = create_reference_image(
            session, brand_id=brand.brand_id, kind="logo", content_type="image/png", image_data=b"a"
        )

        deleted = delete_reference_image(session, brand_id=brand.brand_id, image_id=image.id)

        assert deleted is True
        assert list_reference_images(session, brand_id=brand.brand_id) == []

    def test_unknown_id_returns_false(self, session, tenant_and_brand):
        _, brand = tenant_and_brand

        deleted = delete_reference_image(session, brand_id=brand.brand_id, image_id=uuid.uuid4())

        assert deleted is False
