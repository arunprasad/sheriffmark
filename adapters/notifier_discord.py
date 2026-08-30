"""Discord notifier — posts to an incoming webhook URL, using an embed
(richer formatting, and avoids the 2000-char plain-content limit for
anything but a very large digest). See adapters/notifier_slack.py's
docstring for the "why".
"""

import requests

from adapters.ports import FindingSummary

_BUCKET_COLOR = {"high": 0xE01E5A, "medium": 0xECB22E, "low": 0x9CA3AF}  # Discord embed colors


class DiscordNotifier:
    def send_digest(
        self, destination: str, tenant_name: str, findings: list[FindingSummary]
    ) -> None:
        embeds = _render_discord_embeds(tenant_name, findings)
        resp = requests.post(destination, json={"embeds": embeds}, timeout=10)
        resp.raise_for_status()


def _render_discord_embeds(tenant_name: str, findings: list[FindingSummary]) -> list[dict]:
    by_bucket: dict[str, list[FindingSummary]] = {"high": [], "medium": [], "low": []}
    for finding in findings:
        by_bucket.setdefault(finding.risk_bucket or "low", []).append(finding)

    # Highest-severity bucket present sets the embed color, so the
    # message is visually scannable in a busy channel without opening it.
    color = next(
        (_BUCKET_COLOR[b] for b in ("high", "medium", "low") if by_bucket.get(b)),
        _BUCKET_COLOR["low"],
    )

    fields = []
    for bucket in ("high", "medium", "low"):
        bucket_findings = by_bucket.get(bucket, [])
        if not bucket_findings:
            continue
        value = "\n".join(f"`{f.domain}` ({f.brand_name}, {f.source})" for f in bucket_findings)
        fields.append({"name": f"{bucket.upper()} risk ({len(bucket_findings)})", "value": value})

    return [
        {
            "title": f"{len(findings)} new domain finding(s) for {tenant_name}",
            "color": color,
            "fields": fields,
        }
    ]
