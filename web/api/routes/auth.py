"""Account creation/login for the local email/password provider, plus
the SAML SSO endpoints and a `/providers` endpoint the frontend uses to
decide which login options to show. Server-side config
(Settings.auth_enable_*) is the single source of truth for what's
available — this router never trusts anything the client claims.
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy.orm import Session

from adapters.notifier_smtp import send_raw_email
from shared.config import settings
from shared.db import get_session
from web.api import local_auth, saml_auth
from web.api.session_tokens import issue_token

router = APIRouter(prefix="/api/auth", tags=["auth"])


class ProvidersOut(BaseModel):
    local: bool
    oidc: bool
    saml: bool
    local_requires_verification: bool


@router.get("/providers", response_model=ProvidersOut)
def list_providers() -> ProvidersOut:
    return ProvidersOut(
        local=settings.auth_enable_local,
        oidc=settings.auth_enable_oidc,
        saml=settings.auth_enable_saml,
        local_requires_verification=settings.smtp_configured,
    )


class RegisterIn(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def _min_length(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    email_verification_required: bool = False


def _require_local_enabled() -> None:
    if not settings.auth_enable_local:
        raise HTTPException(status_code=404, detail="Local auth provider is not enabled")


@router.post("/register", response_model=TokenOut, status_code=201)
def register(body: RegisterIn, session: Session = Depends(get_session)) -> TokenOut:
    _require_local_enabled()
    try:
        result = local_auth.register(session, body.email, body.password)
    except local_auth.EmailAlreadyRegistered as e:
        raise HTTPException(status_code=409, detail="Email is already registered") from e

    if result.verification_token is not None:
        base = settings.public_base_url.rstrip("/")
        verify_url = f"{base}/api/auth/verify?token={result.verification_token}"
        body = (
            f"Click to verify your account:\n\n{verify_url}\n\n"
            "If you didn't sign up, ignore this email."
        )
        send_raw_email(settings, result.credential.email, "Verify your SheriffMark account", body)
        return TokenOut(access_token="", email_verification_required=True)

    token = issue_token(session, result.credential.external_id, result.credential.email)
    return TokenOut(access_token=token)


@router.post("/login", response_model=TokenOut)
def login(body: LoginIn, session: Session = Depends(get_session)) -> TokenOut:
    _require_local_enabled()
    try:
        credential = local_auth.authenticate(session, body.email, body.password)
    except local_auth.EmailNotVerified as e:
        raise HTTPException(
            status_code=403, detail="Email not verified — check your inbox"
        ) from e
    except local_auth.InvalidCredentials as e:
        raise HTTPException(status_code=401, detail="Invalid email or password") from e

    token = issue_token(session, credential.external_id, credential.email)
    return TokenOut(access_token=token)


@router.get("/verify", response_class=PlainTextResponse)
def verify(token: str, session: Session = Depends(get_session)) -> str:
    _require_local_enabled()
    try:
        local_auth.verify_email(session, token)
    except local_auth.InvalidCredentials as e:
        raise HTTPException(status_code=400, detail="Invalid or expired verification link") from e
    return "Email verified — you can now sign in."


@router.get("/saml/metadata", response_class=PlainTextResponse)
async def saml_metadata(request: Request) -> str:
    xml, errors = await saml_auth.metadata_xml(request)
    if errors:
        raise HTTPException(status_code=500, detail=f"Invalid SP metadata: {', '.join(errors)}")
    return PlainTextResponse(content=xml, media_type="application/xml")


@router.get("/saml/login")
async def saml_login(request: Request) -> RedirectResponse:
    url = await saml_auth.login_redirect_url(request)
    return RedirectResponse(url, status_code=302)


@router.post("/saml/acs")
async def saml_acs(request: Request, session: Session = Depends(get_session)) -> RedirectResponse:
    redirect_url = await saml_auth.handle_acs(request, session)
    return RedirectResponse(redirect_url, status_code=302)
