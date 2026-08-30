# Multi-stage: Node exists only to build the static frontend bundle: it
# never ships in the runtime image — React/shadcn quality without a
# Node runtime in production.

# ---- stage 1: build the frontend ----
FROM node:22-alpine AS frontend-build
WORKDIR /app/frontend
COPY web/frontend/package.json web/frontend/package-lock.json ./
RUN npm ci
COPY web/frontend/ ./
RUN npm run build

# ---- stage 2: the actual runtime image (no Node here) ----
FROM python:3.12-slim
WORKDIR /app

# libxmlsec1 is python3-saml's native dependency (requirements-saml.txt)
# — installed unconditionally so SAML works out of the box; it's only
# ~a few MB and avoids a second image variant. Removed after pip install
# since only the runtime .so, not the -dev headers, is needed at
# container run time.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libxmlsec1-dev libxmlsec1-openssl pkg-config gcc \
    && rm -rf /var/lib/apt/lists/*

# requirements-postgres.txt (psycopg) is installed unconditionally too,
# same reasoning as SAML above — it's a small pure-C-extension wheel, so
# baking it in means switching DATABASE_URL from the SQLite default to
# Postgres is just an env var change, not a rebuild.
COPY requirements.txt requirements-saml.txt requirements-postgres.txt ./
RUN pip install --no-cache-dir \
    -r requirements.txt -r requirements-saml.txt -r requirements-postgres.txt \
    && apt-get purge -y gcc pkg-config libxmlsec1-dev && apt-get autoremove -y

COPY core/ core/
COPY adapters/ adapters/
COPY shared/ shared/
COPY web/api/ web/api/
COPY web/__init__.py web/__init__.py
COPY migrations/ migrations/
COPY alembic.ini .

COPY --from=frontend-build /app/frontend/dist/ web/frontend/dist/

RUN useradd --create-home --shell /bin/false appuser
USER appuser

EXPOSE 8080
CMD ["uvicorn", "web.api.main:app", "--host", "0.0.0.0", "--port", "8080"]
