from unittest.mock import MagicMock, patch

from adapters.notifier_smtp import SmtpNotifier, _render_digest_text
from adapters.ports import FindingSummary
from shared.config import Settings


def _settings() -> Settings:
    return Settings(
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_user="user",
        smtp_password="pass",
        smtp_from="alerts@example.com",
    )


def test_send_digest_uses_starttls_and_login():
    with patch("adapters.notifier_smtp.smtplib.SMTP") as mock_smtp_cls:
        mock_smtp = MagicMock()
        mock_smtp_cls.return_value.__enter__.return_value = mock_smtp

        notifier = SmtpNotifier(_settings())
        notifier.send_digest(
            "owner@tenant.com",
            "Acme Corp",
            [FindingSummary("acme-login.com", "acme", "generated", "registered", 70, "high")],
        )

        mock_smtp.starttls.assert_called_once()
        mock_smtp.login.assert_called_once_with("user", "pass")
        mock_smtp.send_message.assert_called_once()


def test_send_digest_skips_login_without_credentials():
    settings = _settings()
    settings.smtp_user = ""

    with patch("adapters.notifier_smtp.smtplib.SMTP") as mock_smtp_cls:
        mock_smtp = MagicMock()
        mock_smtp_cls.return_value.__enter__.return_value = mock_smtp

        SmtpNotifier(settings).send_digest("owner@tenant.com", "Acme", [])

        mock_smtp.login.assert_not_called()


def test_render_digest_groups_by_risk_bucket():
    findings = [
        FindingSummary("high1.com", "acme", "ct", "registered", 80, "high"),
        FindingSummary("low1.com", "acme", "generated", "registered", 5, "low"),
        FindingSummary("high2.com", "acme", "generated", "registered", 65, "high"),
    ]

    text = _render_digest_text("Acme", findings)

    high_pos = text.index("HIGH risk")
    low_pos = text.index("LOW risk")
    assert high_pos < low_pos  # high risk surfaces first
    assert "high1.com" in text
    assert "low1.com" in text
