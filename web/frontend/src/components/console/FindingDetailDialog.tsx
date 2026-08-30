import { useEffect, useState } from "react"
import { toast } from "sonner"
import { api, type Finding, type Incident, type ResolutionStatus } from "@/lib/api"
import { describeIncident, incidentLabels, incidentSeverity } from "@/lib/incidents"
import { useAuthedBlobUrl } from "@/hooks/useAuthedBlobUrl"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Textarea } from "@/components/ui/textarea"
import { Label } from "@/components/ui/label"
import { ShieldAlertIcon } from "lucide-react"

const bucketVariant: Record<string, "destructive" | "secondary" | "outline"> = {
  high: "destructive",
  medium: "secondary",
  low: "outline",
}

function riskBucket(score: number | null): "high" | "medium" | "low" {
  if (score === null) return "low"
  if (score >= 60) return "high"
  if (score >= 30) return "medium"
  return "low"
}

const RESOLUTION_LABELS: Record<ResolutionStatus, string> = {
  open: "Open",
  resolved: "Resolved",
  resolved_owned: "Claimed as owned domain",
  resolution_failed: "Resolution failed",
}

export function FindingDetailDialog({
  finding,
  brandId,
  onClose,
  onResolved,
}: {
  finding: Finding | null
  brandId: string
  onClose: () => void
  onResolved: (updated: Finding) => void
}) {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [incidentsLoading, setIncidentsLoading] = useState(false)
  const [note, setNote] = useState("")
  const [pendingAction, setPendingAction] = useState<ResolutionStatus | null>(null)
  const [downloadingReport, setDownloadingReport] = useState(false)

  const domain = finding?.domain ?? null
  const { url: screenshotUrl, loading: screenshotLoading, notFound: noScreenshot } =
    useAuthedBlobUrl(
      domain ? `${domain}:${brandId}` : null,
      () => api.findingScreenshot(domain as string, brandId),
    )

  useEffect(() => {
    if (!domain) {
      setIncidents([])
      return
    }
    setIncidentsLoading(true)
    api
      .listFindingIncidents(domain, brandId)
      .then(setIncidents)
      .catch((e) => toast.error(e instanceof Error ? e.message : String(e)))
      .finally(() => setIncidentsLoading(false))
    setNote("")
  }, [domain, brandId])

  async function handleResolve(status: ResolutionStatus) {
    if (!finding) return
    setPendingAction(status)
    try {
      const updated = await api.resolveFinding(finding.domain, brandId, {
        status,
        note: note.trim() || null,
      })
      onResolved(updated)
      toast.success(
        status === "open" ? "Finding reopened" : `Marked as: ${RESOLUTION_LABELS[status]}`,
      )
      setNote("")
      // Refresh the incident trail in place so the new event shows up
      // without closing the dialog.
      const list = await api.listFindingIncidents(finding.domain, brandId)
      setIncidents(list)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e))
    } finally {
      setPendingAction(null)
    }
  }

  async function handleDownloadReport() {
    if (!finding) return
    setDownloadingReport(true)
    try {
      const { blob, filename } = await api.findingReportPdf(finding.domain, brandId)
      const url = URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = url
      a.download = filename ?? `${finding.domain}-report.pdf`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e))
    } finally {
      setDownloadingReport(false)
    }
  }

  return (
    <Dialog open={finding !== null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-2xl">
        {finding && (
          <>
            <DialogHeader>
              <DialogTitle className="font-mono">{finding.domain}</DialogTitle>
              <DialogDescription>
                Registered via {finding.source} — first seen{" "}
                {new Date(finding.first_seen).toLocaleDateString()}
              </DialogDescription>
            </DialogHeader>

            <div className="grid max-h-[60vh] gap-4 overflow-y-auto sm:grid-cols-2">
              <div className="space-y-4">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge variant={bucketVariant[riskBucket(finding.risk_score)]}>
                    risk: {riskBucket(finding.risk_score)}
                    {finding.risk_score !== null ? ` (${finding.risk_score})` : ""}
                  </Badge>
                  <Badge variant="outline">{RESOLUTION_LABELS[finding.resolution_status]}</Badge>
                  {finding.risk_factors.includes("ip_blocklisted") && (
                    <Badge variant="destructive" className="gap-1">
                      <ShieldAlertIcon className="size-3" />
                      IP blocklisted
                    </Badge>
                  )}
                </div>

                <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-sm">
                  <dt className="text-muted-foreground">Registrar</dt>
                  <dd>{finding.registrar ?? "—"}</dd>
                  <dt className="text-muted-foreground">Abuse contact</dt>
                  <dd>
                    {finding.abuse_email ? (
                      <a href={`mailto:${finding.abuse_email}`} className="underline underline-offset-2">
                        {finding.abuse_email}
                      </a>
                    ) : (
                      "—"
                    )}
                  </dd>
                  <dt className="text-muted-foreground">Created</dt>
                  <dd>{finding.created_date ?? "—"}</dd>
                  <dt className="text-muted-foreground">Last checked</dt>
                  <dd>{new Date(finding.last_checked).toLocaleString()}</dd>
                  {finding.risk_factors.length > 0 && (
                    <>
                      <dt className="text-muted-foreground">Risk factors</dt>
                      <dd>{finding.risk_factors.join(", ")}</dd>
                    </>
                  )}
                  {finding.resolution_note && (
                    <>
                      <dt className="text-muted-foreground">Resolution note</dt>
                      <dd>{finding.resolution_note}</dd>
                    </>
                  )}
                </dl>

                <div>
                  <Label className="mb-2 block text-xs text-muted-foreground">Screenshot</Label>
                  {screenshotLoading ? (
                    <p className="text-sm text-muted-foreground">Loading…</p>
                  ) : noScreenshot || !screenshotUrl ? (
                    <p className="text-sm text-muted-foreground">No screenshot captured yet.</p>
                  ) : (
                    <img
                      src={screenshotUrl}
                      alt={`Screenshot of ${finding.domain}`}
                      className="max-h-48 w-full rounded-md border object-cover object-top"
                    />
                  )}
                </div>
              </div>

              <div className="space-y-2">
                <Label className="text-xs text-muted-foreground">Incident timeline</Label>
                {incidentsLoading ? (
                  <p className="text-sm text-muted-foreground">Loading…</p>
                ) : incidents.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No incidents recorded yet.</p>
                ) : (
                  <ul className="space-y-3">
                    {incidents.map((incident, i) => (
                      <li key={i} className="border-l-2 border-border pl-3">
                        <Badge
                          variant={bucketVariant[incidentSeverity[incident.event_type]]}
                          className="mb-1 h-auto max-w-full whitespace-normal text-left"
                        >
                          {incidentLabels[incident.event_type] ?? incident.event_type}
                        </Badge>
                        <p className="text-sm break-words">{describeIncident(incident)}</p>
                        <p className="text-xs text-muted-foreground">
                          {new Date(incident.detected_at).toLocaleString()}
                        </p>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>

            <div className="space-y-2 border-t pt-4">
              <Label htmlFor="resolution-note" className="text-xs text-muted-foreground">
                Note (optional, shown in the incident timeline)
              </Label>
              <Textarea
                id="resolution-note"
                rows={2}
                value={note}
                onChange={(e) => setNote(e.target.value)}
                placeholder="e.g. registrar takedown request filed, or reason a takedown attempt failed"
              />
            </div>

            <DialogFooter className="flex-wrap justify-start! gap-2 sm:justify-start!">
              {finding.resolution_status !== "open" ? (
                <Button
                  variant="outline"
                  disabled={pendingAction !== null}
                  onClick={() => handleResolve("open")}
                >
                  Reopen
                </Button>
              ) : (
                <>
                  <Button
                    disabled={pendingAction !== null}
                    onClick={() => handleResolve("resolved")}
                  >
                    Mark resolved
                  </Button>
                  <Button
                    variant="secondary"
                    disabled={pendingAction !== null}
                    onClick={() => handleResolve("resolved_owned")}
                  >
                    Claim as owned domain
                  </Button>
                  <Button
                    variant="outline"
                    disabled={pendingAction !== null}
                    onClick={() => handleResolve("resolution_failed")}
                  >
                    Record failed resolution
                  </Button>
                </>
              )}
              <Button
                variant="ghost"
                className="ml-auto"
                disabled={downloadingReport}
                onClick={handleDownloadReport}
              >
                {downloadingReport ? "Preparing…" : "Download report (PDF)"}
              </Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  )
}
