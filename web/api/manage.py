"""Admin CLI for the local email/password provider — bootstrap or
recover an account directly against the database, no running server or
SMTP required. The equivalent of `manage.py createsuperuser` / a
`mysqladmin`-style tool for this project's self-hosted local auth.

This exists because self-hosting has no other account-recovery path:
there's no built-in "forgot password" flow, and the only other way to
fix a lost password is a raw SQL UPDATE. If you can reach
`DATABASE_URL`, you can always recover an account this way — that's
the whole point.

Usage:
    python -m web.api.manage create-account you@example.com
    python -m web.api.manage reset-password you@example.com

Both prompt for the password interactively (never as a CLI argument,
so it never lands in shell history or process listings) and mark the
account verified regardless of SMTP config — a CLI operator with
database access has already proven stronger control than an email
click-through would.
"""

import argparse
import getpass
import sys

from shared.db import SessionLocal
from web.api import local_auth


def _prompt_password() -> str:
    password = getpass.getpass("New password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("Passwords do not match.", file=sys.stderr)
        sys.exit(1)
    if len(password) < 8:
        print("Password must be at least 8 characters.", file=sys.stderr)
        sys.exit(1)
    return password


def create_account(email: str, password: str) -> None:
    session = SessionLocal()
    try:
        result = local_auth.register(session, email, password, auto_verify=True)
        print(f"Account created: {result.credential.email} ({result.credential.external_id})")
    except local_auth.EmailAlreadyRegistered:
        print(f"Error: {email} is already registered. Use reset-password instead.", file=sys.stderr)
        sys.exit(1)
    finally:
        session.close()


def reset_password(email: str, password: str) -> None:
    session = SessionLocal()
    try:
        credential = local_auth.set_password(session, email, password, verify=True)
        print(f"Password reset for {credential.email}.")
    except local_auth.AccountNotFound:
        print(f"Error: no account found for {email}.", file=sys.stderr)
        sys.exit(1)
    finally:
        session.close()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="python -m web.api.manage",
        description=(
            "Bootstrap or recover a local email/password account directly "
            "against the database."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    create_parser = subparsers.add_parser("create-account", help="Create a new local account.")
    create_parser.add_argument("email")

    reset_parser = subparsers.add_parser(
        "reset-password", help="Reset an existing account's password."
    )
    reset_parser.add_argument("email")

    args = parser.parse_args(argv)
    password = _prompt_password()

    if args.command == "create-account":
        create_account(args.email, password)
    else:
        reset_password(args.email, password)


if __name__ == "__main__":
    main()
