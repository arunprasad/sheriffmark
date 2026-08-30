# SheriffMark

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)

Open-source brand-protection monitoring: watches for newly created
domains resembling your brand (typosquats, lookalikes, combosquats) and
alerts you, with evidence to support enforcement action. Self-host it on
your own infrastructure — any cloud, or none at all.

This project is **open source (AGPL-3.0)** and cloud-agnostic by design:
containers, SQLite by default (Postgres opt-in), SMTP, and configurable
auth — built-in email/password by default, plus optional external OIDC
(Supabase Auth, Keycloak, Authentik, Auth0, Zitadel, ...) and SAML 2.0
SSO, any combination enabled per deployment.

## Screenshots

| | |
|---|---|
| ![Brand list](docs/screenshots/brand-list.png) | ![Findings table with risk scores and a blocklist flag](docs/screenshots/findings.png) |
| ![Finding detail: registration, abuse contact, and the incident timeline](docs/screenshots/finding-details.png) | |

## Quickstart

The fastest way to try it: package it once, then run one command.

```bash
git clone https://github.com/arunprasad/sheriffmark.git
cd sheriffmark
pip install -r requirements-dev.txt   # gets `build`, for the step below
./scripts/build.sh                    # builds the frontend, bundles it into a wheel
pipx install dist/sheriffmark-*.whl   # or: pip install dist/sheriffmark-*.whl
sheriffmark serve
```

That's one process on one port (`http://127.0.0.1:8000` by default —
`--host 0.0.0.0` to accept non-local connections) serving both the API
and the built UI, writing to a SQLite file in your current directory.
No Docker, no Postgres, no separate frontend dev server. `sheriffmark
--help` lists the rest (`migrate`, `worker`, `account create-account`/
`reset-password`).

Once a release is published, this collapses further to `pipx install
sheriffmark` with no clone or build step at all — see
[CONTRIBUTING.md](CONTRIBUTING.md#releasing) for the maintainer-side
publish step.

Prefer Docker, or need Postgres? See "Self-hosting" below.

## Layout

```
core/           — pure detection logic (variant generation, RDAP/DNS/CT
                  checks, risk scoring). Zero cloud or tenant awareness.
adapters/       — storage/notifier implementations behind core/'s interfaces
shared/         — DB models, config, cross-cutting logic (e.g. plan limits)
                  used by both web/ and worker/
web/api/        — FastAPI app (JSON API + serves the built frontend)
web/frontend/   — React + shadcn/ui, Vite-built to static assets
worker/         — daily batch pipeline entrypoint
migrations/     — Alembic schema migrations
sheriffmark/    — the `sheriffmark` CLI (pip/pipx entry point) — thin
                  wrappers around the packages above, see Quickstart
scripts/        — build.sh: bundles the frontend + Python package into
                  one installable wheel
```

## Self-hosting

Everything here runs as plain Docker containers — no dependency on any
specific cloud provider. Two deployables:

- **`worker/`** — a scheduled batch job (cron, Cloud Run Job, ECS
  Scheduled Task, a VPS crontab — anything that can run a container on a
  schedule). Does the actual detection work and sends email digests.
- **`web/`** — a long-running HTTP service (the dashboard + API). Auth
  works out of the box (built-in email/password, `AUTH_ENABLE_LOCAL=true`
  by default) — no external provider required. See `.env.example` for
  `AUTH_ENABLE_OIDC`/`AUTH_ENABLE_SAML` if you'd rather point at one.

Both need `DATABASE_URL` and, for `worker/`, SMTP credentials for sending
digests. See `.env.example` for the full list.

**Database: SQLite by default, Postgres when you need it.** Unset
`DATABASE_URL` and the app writes to a single SQLite file — nothing else
to run. This covers the common case (`web/` and `worker/` on the same
host, sharing a mounted volume) with zero extra services. Switch to
Postgres (`DATABASE_URL=postgresql+psycopg://...`, driver already baked
into both Dockerfiles) once you actually need it:

- Real concurrent write load (many brands, frequent scans).
- **`web/` and `worker/` run as separate containers that don't share a
  filesystem** — e.g. `web/` on Cloud Run and `worker/` as an ECS
  Scheduled Task. This is the one case SQLite can't cover at all: it's a
  single file, so both processes need to see the *same* file, which only
  a shared volume/host mount guarantees.

Either way it's a connection-string change, not a code change.

**No built-in "forgot password" flow yet** — if you lose an account's
password, or want to bootstrap the first account without going through
the signup form, use the admin CLI directly against the database (no
running server needed):

```bash
python -m web.api.manage create-account you@example.com
python -m web.api.manage reset-password you@example.com
```

Both prompt for the password interactively. This is also the account-
recovery path for a self-hosted deployment: if you can reach
`DATABASE_URL`, you can always recover an account this way.

Multi-tenancy is built in (useful if you're self-hosting this to watch
brands for multiple clients, e.g. an agency) but there's no billing or
plan-limit gating in this open-source build — usage is unlimited by
default.

## Local development

Nothing to run except Python — `DATABASE_URL` defaults to a SQLite file
in the repo root:

```bash
cp .env.example .env
pip install -r requirements-dev.txt
alembic upgrade head
python -m worker.seed   # optional: one tenant + one brand for manual testing
pytest -q
```

To run the worker for real: `python -m worker.main` (needs SMTP env vars set
in `.env` to actually send a digest; without them, findings still get
written to the DB, only the send step will fail).

Prefer to develop against Postgres instead (matches production more
closely if that's what you'll deploy)? Uncomment `DATABASE_URL` in
`.env`, `pip install -r requirements-postgres.txt`, then:

```bash
docker compose up -d postgres
alembic upgrade head
pytest -q
```

Frontend:

```bash
cd web/frontend
npm install
cp .env.example .env.local   # just VITE_API_BASE_URL for local dev — auth is all backend-side
npm run dev
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the fuller dev workflow and
this project's design principles.

## Running the worker in Docker

With the SQLite default, `web/` and `worker/` just need to share a
mounted directory:

```bash
mkdir -p data
alembic upgrade head   # from the host — writes ./sheriffmark.db
cp sheriffmark.db data/

docker build -f worker/Dockerfile -t domain-watch-worker:latest .
docker run --rm \
  -v "$(pwd)/data:/data" \
  -e DATABASE_URL="sqlite:////data/sheriffmark.db" \
  domain-watch-worker:latest
```

Run `web/`'s image the same way (`-v "$(pwd)/data:/data" -e DATABASE_URL=sqlite:////data/sheriffmark.db`)
so both containers see the same file.

Using Postgres instead:

```bash
docker compose up -d postgres
alembic upgrade head   # from the host, against localhost:5432
python -m worker.seed

docker build -f worker/Dockerfile -t domain-watch-worker:latest .
docker run --rm \
  --network <project-dir-name>_default \
  -e DATABASE_URL="postgresql+psycopg://watch:watch@postgres:5432/watch" \
  domain-watch-worker:latest
```

Note the container reaches Postgres via the compose **service name**
(`postgres`), not `localhost` — `localhost` inside a container means the
container itself. Find the actual network name with `docker network ls`
if `<project-dir-name>_default` doesn't match.

`worker/main.py` handles `SIGTERM`/`SIGINT` gracefully — `docker stop`
(and most schedulers' cancellation signal) lets it wind down at the next
safe point rather than force-killing it.

Both `worker/` and `web/` have also been deployed and verified live on
Google Cloud Run, purely as one example target — nothing in either
Dockerfile is GCP-specific.

## License

[AGPL-3.0](LICENSE). Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).
