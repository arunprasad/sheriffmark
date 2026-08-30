"""Unit tests for the pieces of the SAML SP that don't require a live
IdP or the python3-saml package to be installed: config gating, and the
clear-error behavior when SAML is enabled but the dependency isn't
present. Full ACS assertion validation is exercised manually against a
real IdP rather than mocked here — mocking onelogin.saml2's internals
would mostly test the mock.
"""

from unittest.mock import patch

import pytest
from fastapi import HTTPException

from shared.config import settings
from web.api import saml_auth


class TestRequireConfigured:
    def test_disabled_raises_404(self):
        with patch.object(settings, "auth_enable_saml", False):
            with pytest.raises(HTTPException) as exc_info:
                saml_auth.require_configured()
        assert exc_info.value.status_code == 404

    def test_enabled_but_missing_idp_settings_raises_500(self):
        with patch.object(settings, "auth_enable_saml", True), patch.object(
            settings, "saml_idp_entity_id", ""
        ):
            with pytest.raises(HTTPException) as exc_info:
                saml_auth.require_configured()
        assert exc_info.value.status_code == 500

    def test_fully_configured_does_not_raise(self):
        idp_patches = (
            patch.object(settings, "auth_enable_saml", True),
            patch.object(settings, "saml_idp_entity_id", "https://idp.example.com"),
            patch.object(settings, "saml_idp_sso_url", "https://idp.example.com/sso"),
            patch.object(settings, "saml_idp_x509_cert", "-----BEGIN CERTIFICATE-----fake"),
        )
        with idp_patches[0], idp_patches[1], idp_patches[2], idp_patches[3]:
            saml_auth.require_configured()  # no raise


class TestSamlSettings:
    def test_uses_configured_base_url_and_idp_values(self):
        idp_patches = (
            patch.object(settings, "saml_sp_base_url", "https://sheriffmark.example.com"),
            patch.object(settings, "saml_idp_entity_id", "https://idp.example.com"),
            patch.object(settings, "saml_idp_sso_url", "https://idp.example.com/sso"),
            patch.object(settings, "saml_idp_x509_cert", "cert-data"),
        )
        with idp_patches[0], idp_patches[1], idp_patches[2], idp_patches[3]:
            result = saml_auth._saml_settings()

        assert result["sp"]["entityId"] == "https://sheriffmark.example.com/api/auth/saml/metadata"
        assert result["sp"]["assertionConsumerService"]["url"] == (
            "https://sheriffmark.example.com/api/auth/saml/acs"
        )
        assert result["idp"]["entityId"] == "https://idp.example.com"
        assert result["idp"]["x509cert"] == "cert-data"
