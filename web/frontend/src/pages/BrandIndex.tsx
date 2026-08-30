import { useEffect, useState } from "react"
import { api, type Brand } from "@/lib/api"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { AddBrandDialog } from "@/components/console/AddBrandDialog"
import { AccountSettingsDialog } from "@/components/console/AccountSettingsDialog"

function formatLastScan(iso: string | null): string {
  if (!iso) return "Never"
  return new Date(iso).toLocaleString()
}

export function BrandIndex({
  onOpenBrand,
  onSignOut,
}: {
  onOpenBrand: (brandId: string) => void
  onSignOut: () => void
}) {
  const [brands, setBrands] = useState<Brand[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api
      .listBrands()
      .then(setBrands)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false))
  }, [])

  return (
    <div className="min-h-screen bg-muted/40 p-8">
      <div className="mx-auto max-w-4xl space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-semibold">SheriffMark</h1>
          <div className="flex items-center gap-2">
            <AccountSettingsDialog />
            <Button variant="outline" onClick={onSignOut}>
              Sign out
            </Button>
          </div>
        </div>

        {error && (
          <div className="rounded-md border border-destructive/50 bg-destructive/10 px-4 py-2 text-sm text-destructive">
            {error}
          </div>
        )}

        <div className="flex items-center justify-between">
          <h2 className="text-lg font-medium">Brands</h2>
          <AddBrandDialog onCreated={(brand) => setBrands((prev) => [...prev, brand])} />
        </div>

        {loading ? (
          <p className="text-sm text-muted-foreground">Loading…</p>
        ) : brands.length === 0 ? (
          <div className="rounded-lg border border-dashed p-8 text-center text-sm text-muted-foreground">
            No brands yet — add one to start watching for lookalike domains.
          </div>
        ) : (
          <div className="rounded-lg border bg-background">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Brand</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Last completed scan</TableHead>
                  <TableHead className="text-right">Unresolved findings</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {brands.map((brand) => (
                  <TableRow
                    key={brand.brand_id}
                    className="cursor-pointer hover:bg-muted/50"
                    onClick={() => onOpenBrand(brand.brand_id)}
                  >
                    <TableCell className="font-medium">{brand.name}</TableCell>
                    <TableCell>
                      <Badge variant={brand.active ? "outline" : "secondary"}>
                        {brand.active ? "Active" : "Paused"}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {formatLastScan(brand.last_scan_completed_at)}
                    </TableCell>
                    <TableCell className="text-right">
                      {brand.unresolved_findings_count > 0 ? (
                        <Badge variant="destructive">{brand.unresolved_findings_count}</Badge>
                      ) : (
                        <span className="text-muted-foreground">0</span>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </div>
    </div>
  )
}
