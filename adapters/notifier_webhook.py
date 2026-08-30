"""Generic JSON webhook notifier — for SIEM ingestion, Zapier/n8n, or
any custom integration that isn't Slack/Discord specifically. Same
multi-channel alerting effort as the other channel adapters.

Unlike the Slack/Discord adapters, this one sends structured JSON rather
than a formatted message — the receiving end is assumed to be a program,
not a chat UI.
"""

import requests

from adapters.ports import FindingSummary


class WebhookNotifier:
    def send_digest(
        self, destination: str, tenant_name: str, findings: list[FindingSummary]
    ) -> None:
        payload = {
            "tenant_name": tenant_name,
            "finding_count": len(findings),
            "findings": [
                {
                    "domain": f.domain,
                    "brand_name": f.brand_name,
                    "source": f.source,
                    "status": f.status,
                    "risk_score": f.risk_score,
                    "risk_bucket": f.risk_bucket,
                }
                for f in findings
            ],
        }
        resp = requests.post(destination, json=payload, timeout=10)
        resp.raise_for_status()
