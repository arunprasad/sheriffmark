#!/usr/bin/env bash
# Builds a distributable sheriffmark wheel/sdist: the frontend first
# (Node is only needed here, at build time — never at install time), then
# the Python package via `python -m build`, which bundles the resulting
# web/frontend/dist/ into the wheel (see pyproject.toml's
# [tool.hatch.build.targets.wheel] force-include).
#
# Usage:
#   ./scripts/build.sh
#   pipx install dist/sheriffmark-*.whl        # try it locally
#   twine upload dist/*                        # publish, once you're ready
#
# Needs: Node + npm (frontend build), Python 3.12+ with `build` installed
# (`pip install build`, or it's in requirements-dev.txt).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

echo "==> Building frontend (web/frontend/dist/)"
# VITE_API_BASE_URL="" (not unset) is deliberate and load-bearing: Vite
# bakes env vars into the bundle at build time, and a developer's own
# web/frontend/.env.local (VITE_API_BASE_URL=http://localhost:8000, for
# the two-server local-dev setup where Vite and uvicorn run on different
# ports) still gets loaded during a production build and silently wins
# over an *unset* shell var — found by actually running a packaged build
# and hitting a CORS failure in the browser, not by inspecting the
# config. An empty string, as an actual environment variable, is what
# overrides it: api.ts's `import.meta.env.VITE_API_BASE_URL || ""`
# already treats empty as same-origin/relative, which is exactly right
# once the frontend is served by the same process as the API (see
# sheriffmark/cli.py's `serve` / web/api/main.py's StaticFiles mount).
(cd web/frontend && npm ci && VITE_API_BASE_URL= npm run build)

echo "==> Building Python package (dist/)"
rm -rf dist/
python3 -m build

echo "==> Done. Built:"
ls -la dist/
