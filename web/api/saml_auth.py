"""SAML 2.0 Service Provider, SP-initiated flow, single global IdP per
deployment (see Settings' SAML fields for why: this app targets a
self-hosted single organization, not a SaaS juggling many tenants'
IdPs).

Built on `python3-saml` (the `onelogin.saml2` package), imported lazily
so a deployment that never enables SAML doesn't need its native
dependency (libxmlsec1) installed at all — see requirements-saml.txt and
web/Dockerfile.

Flow:
1. GET  /api/auth/saml/login    -> 302 redirect to the IdP's SSO URL
2. IdP authenticates the user, POSTs a signed assertion back to:
3. POST /api/auth/saml/acs      -> validates the assertion, maps the
   NameID to a "saml:<nameid>" external_id, mints one of this server's
   own session JWTs (web/api/session_tokens.py — same token shape the
   local provider issues, so web/api/auth.py's verification is
   unchanged), and redirects the browser to the frontend with the token
   in a URL fragment.
4. GET  /api/auth/saml/metadata -> this SP's metadata XML, for pasting
   into the IdP's application config.
"""

from urllib.parse import urlencode

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from shared.config import settings
from web.api.session_tokens import issue_token


def _require_saml_dependency():
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth  # noqa: F401
    except ImportError as e:
        raise HTTPException(
            status_code=503,
            detail=(
                "SAML is enabled (AUTH_ENABLE_SAML=true) but python3-saml isn't "
                "installed. Install requirements-saml.txt (and its libxmlsec1 "
                "system dependency) to use SAML."
            ),
        ) from e


def _saml_settings() -> dict:
    base = settings.saml_sp_base_url.rstrip("/")
    return {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": f"{base}/api/auth/saml/metadata",
            "assertionConsumerService": {
                "url": f"{base}/api/auth/saml/acs",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        },
        "idp": {
            "entityId": settings.saml_idp_entity_id,
            "singleSignOnService": {
                "url": settings.saml_idp_sso_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": settings.saml_idp_x509_cert,
        },
    }


async def _request_data(request: Request) -> dict:
    form = await request.form() if request.method == "POST" else {}
    return {
        "https": "on" if request.url.scheme == "https" else "off",
        "http_host": request.url.hostname,
        "server_port": request.url.port or (443 if request.url.scheme == "https" else 80),
        "script_name": request.url.path,
        "get_data": dict(request.query_params),
        "post_data": dict(form),
    }


async def _build_auth(request: Request):
    from onelogin.saml2.auth import OneLogin_Saml2_Auth

    return OneLogin_Saml2_Auth(await _request_data(request), _saml_settings())


def require_configured() -> None:
    if not settings.auth_enable_saml:
        raise HTTPException(status_code=404, detail="SAML auth is not enabled")
    idp_configured = (
        settings.saml_idp_entity_id and settings.saml_idp_sso_url and settings.saml_idp_x509_cert
    )
    if not idp_configured:
        raise HTTPException(
            status_code=500, detail="SAML is enabled but IdP settings are incomplete"
        )


async def login_redirect_url(request: Request) -> str:
    require_configured()
    _require_saml_dependency()
    auth = await _build_auth(request)
    return auth.login()


async def metadata_xml(request: Request) -> tuple[str, list[str]]:
    require_configured()
    _require_saml_dependency()
    from onelogin.saml2.settings import OneLogin_Saml2_Settings

    saml_settings = OneLogin_Saml2_Settings(_saml_settings(), sp_validation_only=True)
    metadata = saml_settings.get_sp_metadata()
    errors = saml_settings.validate_metadata(metadata)
    return metadata.decode(), errors


async def handle_acs(request: Request, session: Session) -> str:
    """Validates the IdP's assertion and returns the frontend redirect
    URL, with a freshly-issued session token in its fragment."""
    require_configured()
    _require_saml_dependency()
    auth = await _build_auth(request)
    auth.process_response()

    errors = auth.get_errors()
    if errors:
        raise HTTPException(
            status_code=401, detail=f"SAML assertion rejected: {', '.join(errors)}"
        )
    if not auth.is_authenticated():
        raise HTTPException(status_code=401, detail="SAML authentication failed")

    name_id = auth.get_nameid()
    attributes = auth.get_attributes()
    email = (attributes.get("email") or attributes.get("mail") or [name_id])[0]
    external_id = f"saml:{name_id}"

    token = issue_token(session, external_id=external_id, email=email)
    redirect_base = settings.saml_frontend_redirect_url
    separator = "&" if "#" in redirect_base else "#"
    return f"{redirect_base}{separator}{urlencode({'token': token})}"
