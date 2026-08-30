"""FastAPI entrypoint — JSON API + serves the built frontend static
assets. Auth is provider-agnostic: local email/password, external OIDC,
and SAML SSO can each be independently enabled via Settings.auth_enable_*
— see web/api/auth.py for how an incoming token gets routed to the
provider that issued it, and web/api/routes/auth.py for the
login/register/SSO endpoints themselves.
"""

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from web.api.routes import account, auth, brands, findings, on_demand_scans

app = FastAPI(title="SheriffMark API")

# Only for local dev, where Vite's dev server (5173) and uvicorn (8000)
# are different origins. In production the frontend is served from this
# same FastAPI app/origin (see the StaticFiles mount below), so those
# requests are same-origin and never touch CORS at all — nothing to add
# here for the deployed Cloud Run URL.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(account.router)
app.include_router(brands.router)
app.include_router(findings.router)
app.include_router(on_demand_scans.router)


# NOT /healthz: confirmed live on Cloud Run that the bare /healthz path
# is intercepted by Google's front-end infrastructure before it ever
# reaches the container (missing the `server: Google Frontend` /
# `x-cloud-trace-context` headers every real request gets — a Kubernetes-
# inherited reserved-path convention, not a bug in this app). Namespacing
# under /api sidesteps it, confirmed with a live redeploy.
@app.get("/api/healthz")
def healthz() -> dict:
    return {"status": "ok"}


# The built frontend, if present — added by the Docker build's frontend
# stage (see web/Dockerfile). Registered last so /api/* above always
# takes priority over this catch-all. Absent during plain
# `uvicorn web.api.main:app` local dev, where Vite's own dev server
# serves the frontend instead.
_frontend_dist = Path(__file__).resolve().parent.parent / "frontend" / "dist"
if _frontend_dist.is_dir():
    app.mount("/", StaticFiles(directory=_frontend_dist, html=True), name="frontend")
