"""Direct tests for the Slack/Discord/generic-webhook notifiers — the
pipeline tests exercise these only via MagicMock, so these confirm the
actual HTTP request shape each one sends."""

from unittest.mock import MagicMock, patch

from adapters.notifier_discord import DiscordNotifier, _render_discord_embeds
from adapters.notifier_slack import SlackNotifier, _render_slack_message
from adapters.notifier_webhook import WebhookNotifier
from adapters.ports import FindingSummary


def _findings():
    return [
        FindingSummary("evil-high.com", "acme", "generated", "registered", 80, "high"),
        FindingSummary("evil-low.com", "acme", "ct", "registered", 5, "low"),
    ]


class TestSlackNotifier:
    @patch("adapters.notifier_slack.requests.post")
    def test_posts_json_text_payload_to_destination(self, mock_post):
        mock_post.return_value = MagicMock(raise_for_status=lambda: None)

        SlackNotifier().send_digest("https://hooks.slack.example/abc", "Acme", _findings())

        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        assert args[0] == "https://hooks.slack.example/abc"
        assert "text" in kwargs["json"]
        assert kwargs["timeout"] == 10

    @patch("adapters.notifier_slack.requests.post")
    def test_raises_on_http_error(self, mock_post):
        import requests

        response = MagicMock()
        response.raise_for_status.side_effect = requests.HTTPError("400")
        mock_post.return_value = response

        try:
            SlackNotifier().send_digest("https://hooks.slack.example/abc", "Acme", _findings())
            raised = False
        except requests.HTTPError:
            raised = True
        assert raised

    def test_message_groups_by_risk_bucket(self):
        text = _render_slack_message("Acme", _findings())
        assert "evil-high.com" in text
        assert "evil-low.com" in text
        assert text.index("HIGH") < text.index("LOW")


class TestDiscordNotifier:
    @patch("adapters.notifier_discord.requests.post")
    def test_posts_embed_payload_to_destination(self, mock_post):
        mock_post.return_value = MagicMock(raise_for_status=lambda: None)

        DiscordNotifier().send_digest("https://discord.example/webhook", "Acme", _findings())

        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        assert args[0] == "https://discord.example/webhook"
        assert "embeds" in kwargs["json"]
        assert len(kwargs["json"]["embeds"]) == 1

    def test_embed_color_reflects_highest_severity_present(self):
        high_and_low = _render_discord_embeds("Acme", _findings())
        only_low = _render_discord_embeds(
            "Acme", [FindingSummary("x.com", "acme", "ct", "registered", 5, "low")]
        )
        assert high_and_low[0]["color"] != only_low[0]["color"]

    def test_embed_fields_cover_every_bucket_present(self):
        embeds = _render_discord_embeds("Acme", _findings())
        field_names = [f["name"] for f in embeds[0]["fields"]]
        assert any("HIGH" in name for name in field_names)
        assert any("LOW" in name for name in field_names)


class TestWebhookNotifier:
    @patch("adapters.notifier_webhook.requests.post")
    def test_posts_structured_json_payload(self, mock_post):
        mock_post.return_value = MagicMock(raise_for_status=lambda: None)

        WebhookNotifier().send_digest("https://example.com/hook", "Acme", _findings())

        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        assert args[0] == "https://example.com/hook"
        payload = kwargs["json"]
        assert payload["tenant_name"] == "Acme"
        assert payload["finding_count"] == 2
        assert payload["findings"][0]["domain"] == "evil-high.com"
        assert payload["findings"][0]["risk_bucket"] == "high"
