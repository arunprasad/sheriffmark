"""SMTP notifier — works unchanged against SES, Resend, Mailgun, or plain
Gmail SMTP; only host/port/credentials in config change. Deliberately
SMTP rather than a vendor-specific REST API, so the adapter never
changes when the provider does.
"""

import smtplib
from email.message import EmailMessage

from adapters.ports import FindingSummary
from shared.config import Settings


class SmtpNotifier:
    def __init__(self, settings: Settings):
        self._settings = settings

    def send_digest(
        self, to_email: str, tenant_name: str, findings: list[FindingSummary]
    ) -> None:
        message = EmailMessage()
        message["Subject"] = f"Domain Name Watch: {len(findings)} new finding(s) for {tenant_name}"
        message["From"] = self._settings.smtp_from
        message["To"] = to_email
        message.set_content(_render_digest_text(tenant_name, findings))

        with smtplib.SMTP(self._settings.smtp_host, self._settings.smtp_port) as smtp:
            smtp.starttls()
            if self._settings.smtp_user:
                smtp.login(self._settings.smtp_user, self._settings.smtp_password)
            smtp.send_message(message)


def send_raw_email(settings: Settings, to_email: str, subject: str, body: str) -> None:
    """Standalone sender for one-off transactional mail (account
    verification, password reset) that doesn't fit the digest shape
    `SmtpNotifier.send_digest` is built around. Same SMTP config, same
    provider-agnostic approach."""
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings.smtp_from
    message["To"] = to_email
    message.set_content(body)

    with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as smtp:
        smtp.starttls()
        if settings.smtp_user:
            smtp.login(settings.smtp_user, settings.smtp_password)
        smtp.send_message(message)


def _render_digest_text(tenant_name: str, findings: list[FindingSummary]) -> str:
    by_bucket: dict[str, list[FindingSummary]] = {"high": [], "medium": [], "low": []}
    for finding in findings:
        by_bucket.setdefault(finding.risk_bucket or "low", []).append(finding)

    lines = [f"New domain findings for {tenant_name}:", ""]
    for bucket in ("high", "medium", "low"):
        bucket_findings = by_bucket.get(bucket, [])
        if not bucket_findings:
            continue
        lines.append(f"{bucket.upper()} risk ({len(bucket_findings)}):")
        for f in bucket_findings:
            lines.append(f"  - {f.domain}  [brand: {f.brand_name}, source: {f.source}]")
        lines.append("")

    return "\n".join(lines)
