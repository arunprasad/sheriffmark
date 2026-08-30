"""The `sheriffmark` command (see pyproject.toml's [project.scripts]).

This is the "download and run" entry point for anyone who installed via
`pip`/`pipx` rather than cloning the repo and running `uvicorn`/`alembic`
by hand — no repo checkout to find alembic.ini or web/frontend/ in, so
this wires the same underlying pieces (migrations/env.py, web.api.main,
worker.main, web.api.manage) together using their installed locations
instead. Every subcommand is a thin wrapper; none of the actual logic
lives here.
"""

import argparse
from pathlib import Path

from alembic import command
from alembic.config import Config


def _alembic_config() -> Config:
    """A programmatic Config rather than pointing at a physical
    alembic.ini — a pip-installed sheriffmark has no repo checkout for
    one to live in. `script_location` just needs to point at wherever
    the `migrations` package landed on disk; migrations/env.py (which
    does the real work — reads shared.config.settings.database_url,
    registers shared.models.Base.metadata) runs exactly as it does for
    a repo checkout's `alembic upgrade head`."""
    import migrations

    cfg = Config()
    cfg.set_main_option("script_location", str(Path(migrations.__file__).resolve().parent))
    return cfg


def _migrate() -> None:
    command.upgrade(_alembic_config(), "head")


def cmd_serve(args: argparse.Namespace) -> None:
    if not args.skip_migrate:
        _migrate()

    import uvicorn

    uvicorn.run("web.api.main:app", host=args.host, port=args.port)


def cmd_migrate(_args: argparse.Namespace) -> None:
    _migrate()
    print("Database is up to date.")


def cmd_worker(_args: argparse.Namespace) -> None:
    from worker.main import main as worker_main

    worker_main()


def cmd_account(args: argparse.Namespace) -> None:
    from web.api.manage import main as manage_main

    manage_main(args.manage_args)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="sheriffmark",
        description=(
            "SheriffMark: self-hosted brand-protection / typosquat monitoring. "
            "See https://github.com/arunprasad/sheriffmark for docs."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve_parser = subparsers.add_parser(
        "serve",
        help="Migrate the database and start the web server "
        "(API + UI, one process, one port).",
    )
    # Defaults to localhost, not 0.0.0.0 — a fresh `pip install && sheriffmark
    # serve` shouldn't silently listen on every interface. Pass --host
    # 0.0.0.0 explicitly for a real deployment (that's what both
    # Dockerfiles already do via the plain `uvicorn` CMD, unaffected by
    # this default).
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8000)
    serve_parser.add_argument(
        "--skip-migrate",
        action="store_true",
        help="Don't run pending migrations before starting (they're a no-op "
        "if the database is already current, so the default is almost "
        "always fine).",
    )
    serve_parser.set_defaults(func=cmd_serve)

    migrate_parser = subparsers.add_parser(
        "migrate", help="Run pending database migrations and exit."
    )
    migrate_parser.set_defaults(func=cmd_migrate)

    worker_parser = subparsers.add_parser(
        "worker", help="Run one pass of the daily detection pipeline, then exit."
    )
    worker_parser.set_defaults(func=cmd_worker)

    account_parser = subparsers.add_parser(
        "account",
        help="Create or recover a local account — "
        "'sheriffmark account create-account you@example.com' or "
        "'sheriffmark account reset-password you@example.com'.",
    )
    account_parser.add_argument("manage_args", nargs=argparse.REMAINDER)
    account_parser.set_defaults(func=cmd_account)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
