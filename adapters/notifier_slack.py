"""Slack notifier — posts to an incoming webhook URL. Multi-channel
alerting alongside email, made cheap by `Notifier` already being a
Protocol (adapters/ports.py) — this is a new implementation, not new
architecture.
"""

import requests

from adapters.ports import FindingSummary

_BUCKET_EMOJI = {"high": "🔴", "medium": "🟠", "low": "⚪"}


class SlackNotifier:
    def send_digest(
        self, destination: str, tenant_name: str, findings: list[FindingSummary]
    ) -> None:
        text = _render_slack_message(tenant_name, findings)
        resp = requests.post(destination, json={"text": text}, timeout=10)
        resp.raise_for_status()


def _render_slack_message(tenant_name: str, findings: list[FindingSummary]) -> str:
    by_bucket: dict[str, list[FindingSummary]] = {"high": [], "medium": [], "low": []}
    for finding in findings:
        by_bucket.setdefault(finding.risk_bucket or "low", []).append(finding)

    lines = [f"*{len(findings)} new domain finding(s) for {tenant_name}*"]
    for bucket in ("high", "medium", "low"):
        bucket_findings = by_bucket.get(bucket, [])
        if not bucket_findings:
            continue
        emoji = _BUCKET_EMOJI[bucket]
        lines.append(f"\n{emoji} *{bucket.upper()}* ({len(bucket_findings)})")
        for f in bucket_findings:
            lines.append(f"• `{f.domain}` — brand: {f.brand_name}, source: {f.source}")

    return "\n".join(lines)
