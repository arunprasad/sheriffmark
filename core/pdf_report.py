"""Evidence dossier export (PDF): WHOIS/RDAP snapshot + DNS records +
screenshot + risk factors + timestamps, per finding, packaged as
something a legal/security team can actually hand to counsel or a
registrar's abuse desk.

Pure function: every field this needs is passed in explicitly (not an
ORM object), so it's testable without a database and has no dependency
on `shared.models` — the same "adapter-facing dataclass, not the ORM
row" boundary `adapters/ports.py`'s `FindingSummary` already draws for
notifications. The caller (`web/api/routes/findings.py`) is
responsible for pulling `Finding`/`FindingEvent` rows and shaping them
into this module's inputs.

Recording only, same as every other enrichment this project ships:
this generates a report of what was found, it does not draft or send
anything to a registrar/abuse desk — that stays a human's decision.
"""

import io
from dataclasses import dataclass, field
from datetime import date, datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Image,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

GENERATOR_NOTE = (
    "Generated automatically by SheriffMark from data acquired by its scanning "
    "pipeline (RDAP/whois, DNS, a live crawl, public abuse blocklists). Not "
    "reviewed by a human and not legal advice — verify before acting on it, "
    "including before contacting a registrar's abuse desk or counsel."
)


@dataclass(frozen=True)
class IncidentEntry:
    event_type: str
    detected_at: datetime
    description: str


@dataclass(frozen=True)
class FindingReportData:
    domain: str
    brand_name: str
    source: str  # "generated" | "ct" | "manual" | "on_demand"
    status: str
    registrar: str | None
    created_date: date | None
    abuse_email: str | None
    risk_score: int | None
    risk_factors: list[str]
    resolution_status: str
    resolution_note: str | None
    first_seen: datetime
    last_checked: datetime
    dns_snapshot: dict = field(default_factory=dict)
    website_snapshot: dict = field(default_factory=dict)
    screenshot_data: bytes | None = None
    incidents: list[IncidentEntry] = field(default_factory=list)


def describe_incident(event_type: str, details: dict) -> str:
    """Backend counterpart to web/frontend/src/lib/incidents.ts's
    describeIncident — same event_type -> human-readable-line mapping,
    kept in sync by hand since one's TypeScript and one's Python. Used
    to pre-render each incident's detail line for the PDF (the
    frontend renders straight from `details` itself instead)."""
    d = details or {}
    if event_type == "registered":
        if d.get("registrar"):
            return f"Registrar: {d['registrar']}"
        return "Registration detected, registrar unknown"
    if event_type == "whois_change":
        return f"{d.get('old', 'unknown')} → {d.get('new', 'unknown')}"
    if event_type == "dns_change":
        parts = []
        for record_type, change in d.items():
            old = ", ".join(change.get("old", [])) or "—"
            new = ", ".join(change.get("new", [])) or "—"
            parts.append(f"{record_type.upper()}: {old} → {new}")
        return "; ".join(parts)
    if event_type == "ip_blocklisted":
        ips = d.get("ips") or {}
        parts = []
        for ip, lists in ips.items():
            list_names = ", ".join(lists.keys()) if isinstance(lists, dict) else ""
            parts.append(f"{ip} ({list_names})" if list_names else ip)
        return f"Listed: {'; '.join(parts)}" if parts else "IP flagged on a public blocklist"
    if event_type == "website_change":
        snippet = d.get("snippet")
        return f'New content: "{str(snippet)[:100]}…"' if snippet else "Page content changed"
    if event_type == "form_detected":
        suffix = ", including a password field" if d.get("has_password_field") else ""
        return f"{d.get('form_count', 1)} form(s){suffix}"
    if event_type == "redirect_detected":
        return f"→ {d.get('target')}"
    if event_type == "spa_detected":
        signals = d.get("signals") or []
        if signals:
            return (
                f"Detected via: {', '.join(signals)} — needs a "
                "browser-based crawler to see real content"
            )
        return "Needs a browser-based crawler to see real content"
    if event_type in ("logo_match_detected", "site_clone_detected"):
        filename = d.get("reference_filename", "unnamed")
        return f'Matched reference image "{filename}" ({d.get("detail", "")})'
    if event_type in ("resolved", "resolved_owned", "resolution_failed", "reopened"):
        return d.get("note") or event_type.replace("_", " ").capitalize()
    return str(d)


def _risk_bucket(score: int | None) -> str:
    if score is None:
        return "low"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def _kv_table(rows: list[tuple[str, str]], styles) -> Table:
    data = [
        [Paragraph(f"<b>{label}</b>", styles["Small"]), Paragraph(value or "—", styles["Small"])]
        for label, value in rows
    ]
    table = Table(data, colWidths=[1.6 * inch, 4.4 * inch])
    table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("LINEBELOW", (0, 0), (-1, -2), 0.5, colors.HexColor("#e5e5e5")),
            ]
        )
    )
    return table


def build_finding_report(data: FindingReportData, generated_at: datetime | None = None) -> bytes:
    """Renders `data` into a one-finding PDF evidence report. Never
    raises on missing/partial data (a finding with no screenshot, no
    incidents, or no DNS acquisition yet is the common case for a
    just-discovered or still-unregistered candidate) — every section
    degrades to an explicit "not available" rather than erroring."""
    generated_at = generated_at or datetime.now()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=LETTER,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        title=f"SheriffMark evidence report — {data.domain}",
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("Small", parent=styles["Normal"], fontSize=9, leading=12))
    styles.add(
        ParagraphStyle(
            "SectionHeading",
            parent=styles["Heading2"],
            spaceBefore=14,
            spaceAfter=6,
            textColor=colors.HexColor("#111111"),
        )
    )
    styles.add(
        ParagraphStyle(
            "Footnote",
            parent=styles["Normal"],
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#666666"),
        )
    )

    story = []

    story.append(Paragraph("Domain Evidence Report", styles["Title"]))
    story.append(
        Paragraph(f"<font face='Courier-Bold' size=14>{data.domain}</font>", styles["Normal"])
    )
    story.append(Spacer(1, 4))
    story.append(
        Paragraph(
            f"Brand: {data.brand_name} &nbsp;|&nbsp; Generated: "
            f"{generated_at.strftime('%Y-%m-%d %H:%M UTC')}",
            styles["Small"],
        )
    )
    story.append(Spacer(1, 12))

    bucket = _risk_bucket(data.risk_score)
    bucket_color = {"high": "#b91c1c", "medium": "#b45309", "low": "#4b5563"}[bucket]
    score_text = f"{data.risk_score}" if data.risk_score is not None else "n/a"
    story.append(
        Paragraph(
            f"Risk: <font color='{bucket_color}'><b>{bucket.upper()} ({score_text})</b></font>"
            f" &nbsp;|&nbsp; Resolution: <b>{data.resolution_status.replace('_', ' ')}</b>",
            styles["Normal"],
        )
    )

    story.append(Paragraph("Registration", styles["SectionHeading"]))
    story.append(
        _kv_table(
            [
                ("Status", data.status),
                ("Source", data.source),
                ("Registrar", data.registrar or "Unknown"),
                ("Created", data.created_date.isoformat() if data.created_date else "Unknown"),
                ("Abuse contact", data.abuse_email or "Unknown"),
                ("First seen", data.first_seen.strftime("%Y-%m-%d %H:%M UTC")),
                ("Last checked", data.last_checked.strftime("%Y-%m-%d %H:%M UTC")),
            ],
            styles,
        )
    )

    story.append(Paragraph("Risk factors", styles["SectionHeading"]))
    story.append(
        Paragraph(
            ", ".join(data.risk_factors) if data.risk_factors else "None recorded.",
            styles["Small"],
        )
    )

    story.append(Paragraph("DNS records", styles["SectionHeading"]))
    dns_rows = [
        ("A", ", ".join(data.dns_snapshot.get("a", [])) or "None"),
        ("MX", ", ".join(data.dns_snapshot.get("mx", [])) or "None"),
        ("NS", ", ".join(data.dns_snapshot.get("ns", [])) or "None"),
    ]
    blocklist = data.dns_snapshot.get("blocklist") or {}
    if blocklist:
        parts = []
        for ip, lists in blocklist.items():
            list_names = ", ".join(lists.keys()) if isinstance(lists, dict) else ""
            parts.append(f"{ip} ({list_names})" if list_names else ip)
        dns_rows.append(("Blocklisted", "; ".join(parts)))
    story.append(_kv_table(dns_rows, styles))

    story.append(Paragraph("Website", styles["SectionHeading"]))
    ws = data.website_snapshot
    if ws:
        story.append(
            _kv_table(
                [
                    ("Reachable", "Yes" if ws.get("reachable") else "No"),
                    ("Status code", str(ws.get("status_code")) if ws.get("status_code") else "—"),
                    ("Final URL", ws.get("final_url") or "—"),
                    (
                        "Forms",
                        f"{ws.get('form_count', 0)} form(s)"
                        + (", including a password field" if ws.get("has_password_field") else "")
                        if ws.get("has_forms")
                        else "None detected",
                    ),
                    ("Redirects to", ws.get("redirect_target") or "—"),
                    (
                        "Client-rendered app (SPA)",
                        "Yes — content below may be incomplete" if ws.get("is_spa") else "No",
                    ),
                ],
                styles,
            )
        )
    else:
        story.append(Paragraph("No website data acquired yet.", styles["Small"]))

    story.append(Paragraph("Screenshot", styles["SectionHeading"]))
    if data.screenshot_data:
        try:
            img = Image(io.BytesIO(data.screenshot_data), width=5.5 * inch, height=3.44 * inch)
            story.append(img)
        except Exception:
            story.append(Paragraph("Screenshot could not be embedded.", styles["Small"]))
    else:
        story.append(Paragraph("No screenshot captured yet.", styles["Small"]))

    story.append(Paragraph("Incident timeline", styles["SectionHeading"]))
    if data.incidents:
        rows = [
            (
                i.detected_at.strftime("%Y-%m-%d %H:%M UTC"),
                i.event_type.replace("_", " "),
                i.description,
            )
            for i in sorted(data.incidents, key=lambda i: i.detected_at, reverse=True)
        ]
        table_data = [["When", "Event", "Detail"]] + [list(r) for r in rows]
        table = Table(
            [[Paragraph(f"<b>{c}</b>", styles["Small"]) for c in table_data[0]]]
            + [[Paragraph(c, styles["Small"]) for c in row] for row in table_data[1:]],
            colWidths=[1.3 * inch, 1.3 * inch, 3.4 * inch],
        )
        table.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e5e5")),
                    ("LINEBELOW", (0, 0), (-1, 0), 1, colors.HexColor("#999999")),
                ]
            )
        )
        story.append(table)
    else:
        story.append(Paragraph("No incidents recorded yet.", styles["Small"]))

    if data.resolution_note:
        story.append(Paragraph("Resolution note", styles["SectionHeading"]))
        story.append(Paragraph(data.resolution_note, styles["Small"]))

    story.append(Spacer(1, 18))
    story.append(KeepTogether([Paragraph(GENERATOR_NOTE, styles["Footnote"])]))

    doc.build(story)
    return buffer.getvalue()
