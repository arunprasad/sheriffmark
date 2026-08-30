import { useEffect, useState } from "react"
import { toast } from "sonner"
import { api, type Finding } from "@/lib/api"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { FindingDetailDialog } from "@/components/console/FindingDetailDialog"
import { DownloadIcon, ShieldAlertIcon } from "lucide-react"

function riskBucket(score: number | null): "high" | "medium" | "low" {
  if (score === null) return "low"
  if (score >= 60) return "high"
  if (score >= 30) return "medium"
  return "low"
}

const bucketVariant: Record<string, "destructive" | "secondary" | "outline"> = {
  high: "destructive",
  medium: "secondary",
  low: "outline",
}

const FILTER_OPTIONS: { value: string; label: string }[] = [
  { value: "open", label: "Open" },
  { value: "all", label: "All" },
  { value: "resolved", label: "Resolved" },
  { value: "resolved_owned", label: "Claimed as owned" },
  { value: "resolution_failed", label: "Resolution failed" },
]

export function FindingsTab({ brandId }: { brandId: string }) {
  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState("open")
  const [selected, setSelected] = useState<Finding | null>(null)

  function reload() {
    setLoading(true)
    api
      .listFindings(brandId, {
        status: "registered",
        resolution_status: filter === "all" ? undefined : filter,
      })
      .then(setFindings)
      .catch((e) => toast.error(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    reload()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [brandId, filter])

  async function handleExport() {
    try {
      const { blob, filename } = await api.exportFindingsCsv(brandId)
      const url = URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = url
      a.download = filename ?? "findings.csv"
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e))
    }
  }

  function handleResolved(updated: Finding) {
    setSelected(updated)
    // The row's resolution status just changed — if it no longer
    // matches the active filter, drop it from the list rather than
    // waiting for the next reload to make that obvious.
    setFindings((prev) =>
      prev
        .map((f) => (f.domain === updated.domain ? updated : f))
        .filter((f) => filter === "all" || f.resolution_status === filter),
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <Select value={filter} onValueChange={(value) => value && setFilter(value)}>
          <SelectTrigger size="sm">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {FILTER_OPTIONS.map((opt) => (
              <SelectItem key={opt.value} value={opt.value}>
                {opt.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button variant="outline" size="sm" onClick={handleExport}>
          <DownloadIcon />
          Export CSV
        </Button>
      </div>

      {loading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : findings.length === 0 ? (
        <div className="rounded-lg border border-dashed p-8 text-center text-sm text-muted-foreground">
          {filter === "open"
            ? "No open findings — either nothing's turned up yet, or everything's been handled."
            : "No findings match this filter."}
        </div>
      ) : (
        <div className="rounded-lg border bg-background">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Domain</TableHead>
                <TableHead>Source</TableHead>
                <TableHead>Risk</TableHead>
                <TableHead>Registrar</TableHead>
                <TableHead>First seen</TableHead>
                <TableHead>Resolution</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {findings.map((f) => {
                const bucket = riskBucket(f.risk_score)
                return (
                  <TableRow
                    key={f.domain}
                    className="cursor-pointer hover:bg-muted/50"
                    onClick={() => setSelected(f)}
                  >
                    <TableCell className="font-mono text-sm">
                      <span className="inline-flex items-center gap-1.5">
                        {f.domain}
                        {f.risk_factors.includes("ip_blocklisted") && (
                          <span title="IP flagged on a public abuse/spam blocklist">
                            <ShieldAlertIcon
                              className="size-3.5 shrink-0 text-destructive"
                              aria-label="IP flagged on a public abuse/spam blocklist"
                            />
                          </span>
                        )}
                      </span>
                    </TableCell>
                    <TableCell>{f.source}</TableCell>
                    <TableCell>
                      <Badge variant={bucketVariant[bucket]}>
                        {bucket} {f.risk_score !== null ? `(${f.risk_score})` : ""}
                      </Badge>
                    </TableCell>
                    <TableCell>{f.registrar ?? "—"}</TableCell>
                    <TableCell>{new Date(f.first_seen).toLocaleDateString()}</TableCell>
                    <TableCell>
                      {f.resolution_status === "open" ? (
                        <span className="text-muted-foreground">Open</span>
                      ) : (
                        <Badge
                          variant={f.resolution_status === "resolution_failed" ? "destructive" : "outline"}
                        >
                          {f.resolution_status.replace("_", " ")}
                        </Badge>
                      )}
                    </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        </div>
      )}

      <FindingDetailDialog
        finding={selected}
        brandId={brandId}
        onClose={() => setSelected(null)}
        onResolved={handleResolved}
      />
    </div>
  )
}
