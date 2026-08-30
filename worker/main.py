"""Worker entrypoint — the daily batch pipeline.

Deliberately a plain run-to-completion script, not a cloud-function
handler(event, context) — this way, whatever scheduler invokes it
(Cloud Scheduler + Cloud Run Job, a VPS cron, a GitHub Actions cron)
just runs the container; this script doesn't know or care who
triggered it.

Handles SIGTERM/SIGINT for graceful shutdown — both `docker stop` and a
Cloud Run Job cancellation send SIGTERM and then force-kill after a
grace period if the process hasn't exited. Found live that without
this, the worker gets SIGKILLed mid-run rather than winding down and
committing whatever it had already done.
"""

import logging
import signal
import threading

from adapters.notifier_discord import DiscordNotifier
from adapters.notifier_slack import SlackNotifier
from adapters.notifier_smtp import SmtpNotifier
from adapters.notifier_webhook import WebhookNotifier
from shared.config import settings
from shared.db import SessionLocal
from worker.pipeline import run_daily_pipeline

logging.basicConfig(level=logging.INFO)

_shutdown_event = threading.Event()


def _handle_shutdown_signal(signum, _frame) -> None:
    logging.warning("received signal %s — will stop at the next safe point", signum)
    _shutdown_event.set()


def main() -> None:
    signal.signal(signal.SIGTERM, _handle_shutdown_signal)
    signal.signal(signal.SIGINT, _handle_shutdown_signal)

    session = SessionLocal()
    # All four channels are always available structurally — which ones
    # actually fire per tenant depends on what destination that tenant
    # has configured (see worker/pipeline.py's dispatch_notifications).
    notifiers = {
        "email": SmtpNotifier(settings),
        "slack": SlackNotifier(),
        "discord": DiscordNotifier(),
        "webhook": WebhookNotifier(),
    }
    try:
        summary = run_daily_pipeline(session, notifiers, should_stop=_shutdown_event.is_set)
        if _shutdown_event.is_set():
            logging.info("worker run stopped early by signal: %s", summary)
        else:
            logging.info("worker run complete: %s", summary)
    finally:
        session.close()


if __name__ == "__main__":
    main()
