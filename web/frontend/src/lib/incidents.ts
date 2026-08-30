import type { Incident, IncidentEventType } from "@/lib/api"

export const incidentLabels: Record<IncidentEventType, string> = {
  registered: "Domain registered",
  whois_change: "WHOIS registrar changed",
  dns_change: "DNS records changed",
  ip_blocklisted: "IP flagged on a public abuse/spam list",
  website_change: "Website content changed",
  form_detected: "Form detected on site",
  redirect_detected: "Redirects to another domain",
  spa_detected: "Client-rendered app (SPA) — content not fully visible",
  logo_match_detected: "Your logo detected on this page",
  site_clone_detected: "Page closely resembles your reference screenshot",
  resolved: "Marked resolved",
  resolved_owned: "Claimed as owned domain",
  resolution_failed: "Resolution attempt failed",
  reopened: "Reopened",
}

export const incidentSeverity: Record<IncidentEventType, "high" | "medium" | "low"> = {
  form_detected: "high",
  redirect_detected: "high",
  logo_match_detected: "high",
  site_clone_detected: "high",
  ip_blocklisted: "high",
  resolution_failed: "high",
  whois_change: "medium",
  dns_change: "medium",
  website_change: "medium",
  spa_detected: "medium",
  reopened: "medium",
  registered: "low",
  resolved: "low",
  resolved_owned: "low",
}

/** Renders one incident's `details` payload as a short human-readable
 * line — shape differs per event_type (see worker/pipeline.py's
 * _record_finding for what each type actually carries). */
export function describeIncident(incident: Incident): string {
  const d = incident.details as Record<string, unknown>

  switch (incident.event_type) {
    case "registered":
      return d.registrar ? `Registrar: ${d.registrar}` : "Registration detected, registrar unknown"
    case "whois_change":
      return `${d.old ?? "unknown"} → ${d.new ?? "unknown"}`
    case "dns_change": {
      const parts: string[] = []
      for (const [recordType, change] of Object.entries(d)) {
        const c = change as { old: string[]; new: string[] }
        parts.push(`${recordType.toUpperCase()}: ${c.old.join(", ") || "—"} → ${c.new.join(", ") || "—"}`)
      }
      return parts.join("; ")
    }
    case "ip_blocklisted": {
      const ips = (d.ips as Record<string, Record<string, string[]>>) ?? {}
      const parts = Object.entries(ips).map(([ip, lists]) => {
        const listNames = Object.keys(lists)
        return listNames.length ? `${ip} (${listNames.join(", ")})` : ip
      })
      return parts.length ? `Listed: ${parts.join("; ")}` : "IP flagged on a public blocklist"
    }
    case "website_change":
      return d.snippet ? `New content: "${String(d.snippet).slice(0, 100)}…"` : "Page content changed"
    case "form_detected":
      return `${d.form_count ?? 1} form(s)${d.has_password_field ? ", including a password field" : ""}`
    case "redirect_detected":
      return `→ ${d.target}`
    case "spa_detected": {
      const signals = Array.isArray(d.signals) ? (d.signals as string[]) : []
      return signals.length
        ? `Detected via: ${signals.join(", ")} — needs a browser-based crawler to see real content`
        : "Needs a browser-based crawler to see real content"
    }
    case "logo_match_detected":
    case "site_clone_detected":
      return `Matched reference image "${d.reference_filename ?? "unnamed"}" (${d.detail ?? ""})`
    case "resolved":
    case "resolved_owned":
    case "resolution_failed":
    case "reopened":
      return typeof d.note === "string" && d.note ? d.note : incidentLabels[incident.event_type]
    default:
      return JSON.stringify(d)
  }
}
