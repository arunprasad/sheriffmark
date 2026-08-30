# The worker: a plain run-to-completion batch job, not a cloud-function
# handler. This image runs identically on a local `docker run`, a Cloud
# Run Job, an ECS Scheduled Task, a VPS cron, or anywhere else a
# scheduler can invoke a container.
#
# Single-stage: the worker is pure Python, no frontend build step (that
# only applies to web/, which gets its own multi-stage Dockerfile).

FROM python:3.12-slim

WORKDIR /app

# Only production deps — requirements-dev.txt's pytest/ruff have no
# business in the deployed image. requirements-postgres.txt (psycopg)
# is baked in unconditionally — a small pure-C-extension wheel — so
# switching DATABASE_URL from the SQLite default to Postgres is just an
# env var change, not a rebuild.
COPY requirements.txt requirements-postgres.txt .
RUN pip install --no-cache-dir -r requirements.txt -r requirements-postgres.txt

# Optional: core/browser_crawler.py's SPA-rendering fallback
# (requirements-browser.txt) needs Playwright + a real Chromium
# download — real weight (~300MB+), so it's opt-in, not baked in by
# default. Without it, SPA-flagged domains are still detected and
# logged (core/spa_detection.py); they just don't get a rendered
# snapshot. Uncomment to enable:
#
# COPY requirements-browser.txt .
# RUN pip install --no-cache-dir -r requirements-browser.txt \
#     && playwright install --with-deps chromium

COPY core/ core/
COPY adapters/ adapters/
COPY shared/ shared/
COPY worker/ worker/
COPY migrations/ migrations/
COPY alembic.ini .

# Non-root: no reason this process needs root inside the container.
RUN useradd --create-home --shell /bin/false appuser
USER appuser

CMD ["python", "-m", "worker.main"]
