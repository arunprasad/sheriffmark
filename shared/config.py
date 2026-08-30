"""Runtime configuration, sourced entirely from environment variables.

Deliberately platform-agnostic: nothing here reads a cloud-specific secrets
API. Whoever runs the container (docker-compose locally, Cloud Run, ECS,
a plain VPS) is responsible for injecting these however it likes.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # SQLite by default — a single file, zero extra services, so
    # `pip install && alembic upgrade head && uvicorn ...` works with
    # nothing else running. Switch to Postgres by setting DATABASE_URL
    # (and installing requirements-postgres.txt) once you actually need
    # it: real concurrent write load, or — the one case SQLite can't
    # cover at all — running `web/` and `worker/` as separate containers
    # that don't share a filesystem/volume (e.g. split across two
    # different managed services). See README.md's "Self-hosting"
    # section for both paths.
    database_url: str = "sqlite:///./sheriffmark.db"

    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "alerts@example.com"

    # Which auth providers this server accepts. Self-hosters pick what
    # fits their deployment — a lone local instance needs nothing but
    # `local`; an org wiring up Okta/Azure AD turns on `saml`; a shop
    # already running its own OIDC provider (Keycloak, Authentik, Auth0)
    # turns on `oidc`. Any combination can be active at once — verify_token
    # (web/api/auth.py) routes each incoming JWT by its issuer claim.
    auth_enable_local: bool = True
    auth_enable_oidc: bool = False
    auth_enable_saml: bool = False

    # Local email/password provider. Tokens are self-issued (RS256,
    # keypair generated on first use and persisted in the `signing_keys`
    # table — see web/api/crypto_keys.py) so verification reuses the same
    # "JWT + JWKS-shaped lookup" code path as the external OIDC provider,
    # rather than being a second, differently-shaped auth mechanism.
    auth_local_issuer: str = "sheriffmark-local"
    # This server's own externally-reachable URL — used to build links
    # that leave the server (email verification links). Separate from
    # saml_sp_base_url below: SAML self-hosters usually want the same
    # value in both, but SAML's must exactly match what's registered
    # with the IdP, so it stays its own explicit setting rather than
    # silently inheriting this one.
    public_base_url: str = "http://localhost:8000"

    # External OIDC provider (Supabase Auth, Keycloak, Auth0, Azure AD via
    # OIDC, ...). `auth_oidc_audience`/`algorithms` default to Supabase's
    # conventions for backward compatibility with existing deployments,
    # but are overridable for any other OIDC-compliant issuer.
    auth_jwks_url: str = ""
    auth_oidc_issuer: str = ""
    auth_oidc_audience: str = "authenticated"
    auth_oidc_algorithms: str = "ES256,RS256"

    # SAML 2.0 Service Provider config. Deliberately global/single-IdP —
    # this app is aimed at a self-hosted single organization standing up
    # its own instance, not a SaaS juggling many tenants' IdPs, so one
    # IdP per deployment keeps this simple. See web/api/saml_auth.py.
    saml_idp_entity_id: str = ""
    saml_idp_sso_url: str = ""
    saml_idp_x509_cert: str = ""
    saml_sp_base_url: str = "http://localhost:8000"
    # Where to send the browser after a successful SSO login, with the
    # session token in the URL fragment (never sent to any server, so
    # this is safe over plain redirects). Defaults to "/" since in
    # production the frontend is served from this same FastAPI app; a
    # split local-dev setup (Vite on a different port) can point this at
    # the Vite origin instead.
    saml_frontend_redirect_url: str = "/"

    stripe_secret_key: str = ""
    stripe_webhook_secret: str = ""

    @property
    def smtp_configured(self) -> bool:
        """Gates email-verification/password-reset flows (web/api/local_auth.py):
        self-hosters who haven't wired up SMTP yet still get working
        signup, just without a verification step — requiring SMTP to
        create an account at all would break the zero-dependency,
        keep-it-private promise of the local provider."""
        return bool(self.smtp_host)


settings = Settings()
