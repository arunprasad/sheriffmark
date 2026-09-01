# Contributing

Thanks for considering a contribution. This project is small and young —
process is deliberately light.

## Before you start

For anything beyond a small fix (a new feature, a schema change, a
behavior change), open an issue first to discuss the approach. Saves
everyone the pain of a large PR going in a direction that doesn't fit.

## Branching workflow

Nothing lands on `main` directly — every change goes through a branch
and a PR, squash-merged when it's done:

```bash
git checkout main && git pull
git checkout -b <short-description>   # e.g. abuse-contact-lookup, fix-sqlite-timestamps
# ... commit as many times as you want while iterating ...
git push -u origin <short-description>
```

Then open a PR on GitHub and use **"Squash and merge"** once it's ready
— `main`'s history is one commit per shipped change, not a replay of
every intermediate commit made while getting there. `main` is also
branch-protected: direct pushes are rejected, a PR is the only way in.

Delete the branch after merging (GitHub's UI offers this on the PR page
once it's merged) — there's no reason to keep it around once its commit
is on `main`.

## Local development

See [README.md](README.md#local-development) for getting the backend +
frontend running. In short — SQLite by default, no separate DB service:

```bash
cp .env.example .env
pip install -r requirements-dev.txt
alembic upgrade head
pytest -q
ruff check .
```

Frontend:

```bash
cd web/frontend
npm install
cp .env.example .env.local   # fill in your own Supabase (or other OIDC) values
npm run dev
```

## Before opening a PR

- `pytest -q` passes
- `ruff check .` is clean
- `npm run build` succeeds in `web/frontend/` if you touched it
- New behavior has a test — this project has been built with a real live
  service verified at every step (real DB, real external call, real
  running container, not just mocks); tests are how that discipline
  continues without a human re-verifying everything by hand each time

## Design principles this project follows (please keep following them)

- **`core/` stays pure** — no cloud SDKs, no DB, no tenant/billing
  concepts. It's the actual detection logic (variant generation,
  RDAP/DNS/CT checks, risk scoring) and should stay portable and
  independently testable.
- **Cloud-agnostic by construction** — containers, SQLite by default
  (Postgres opt-in), SMTP, JWT/JWKS auth. Nothing in this codebase
  should require one specific cloud provider.
- **Additive migrations, not rewrites** — once a migration has run
  against any real database (yours or anyone else's), don't edit it;
  add a new one. `migrations/versions/` has examples of exactly this
  pattern (fixing a bug found after the fact, adding new columns). The
  one exception: the whole history was squashed into one baseline on
  2026-08-29 to move to portable column types (SQLite support) — safe
  *only* because this project had never had a real deployment before
  that point. That justification doesn't apply again; don't treat it as
  a precedent for squashing later.
- **Verify against something real** — a passing test suite is good; a
  live-verified round trip (real DB, real external call, real running
  container) is better. Mock what you must, but don't mock what you can
  actually run.

## Releasing

`sheriffmark`'s version lives in exactly one place: `[project].version`
in `pyproject.toml` (`sheriffmark.__version__` in
`sheriffmark/__init__.py` is a separate, cosmetic copy — bump both
together).

```bash
./scripts/build.sh        # builds the frontend, bundles it into dist/*.whl + *.tar.gz
pipx install --force dist/sheriffmark-*.whl   # smoke-test it locally first
twine upload dist/*       # needs a PyPI account + API token — not automated in CI
```

Nothing here auto-publishes on tag/merge — a release is a deliberate,
manual `twine upload`, since it needs a PyPI token that only whoever
owns the `sheriffmark` PyPI project should hold. `pip install build
twine` if you don't have them.

## License

By contributing, you agree your contribution is licensed under this
project's [AGPL-3.0](LICENSE).
