import { useEffect, useState } from "react"
import { toast } from "sonner"
import { api, type Brand } from "@/lib/api"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { FindingsTab } from "@/components/console/FindingsTab"
import { SettingsTab } from "@/components/console/SettingsTab"
import { ArrowLeftIcon } from "lucide-react"

export function BrandConsole({
  brandId,
  onBack,
  onSignOut,
}: {
  brandId: string
  onBack: () => void
  onSignOut: () => void
}) {
  const [brand, setBrand] = useState<Brand | null>(null)
  const [loading, setLoading] = useState(true)
  const [tab, setTab] = useState("findings")

  useEffect(() => {
    setLoading(true)
    api
      .listBrands()
      .then((brands) => {
        const found = brands.find((b) => b.brand_id === brandId)
        if (!found) {
          toast.error("Brand not found")
          onBack()
          return
        }
        setBrand(found)
      })
      .catch((e) => toast.error(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [brandId])

  return (
    <div className="min-h-screen bg-muted/40 p-8">
      <div className="mx-auto max-w-4xl space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Button variant="ghost" size="icon-sm" onClick={onBack} aria-label="Back to brands">
              <ArrowLeftIcon />
            </Button>
            {loading || !brand ? (
              <h1 className="text-2xl font-semibold">Loading…</h1>
            ) : (
              <div className="flex items-center gap-2">
                <h1 className="text-2xl font-semibold">{brand.name}</h1>
                {!brand.active && <Badge variant="secondary">Paused</Badge>}
              </div>
            )}
          </div>
          <Button variant="outline" onClick={onSignOut}>
            Sign out
          </Button>
        </div>

        {!loading && brand && (
          <Tabs value={tab} onValueChange={setTab}>
            <TabsList>
              <TabsTrigger value="findings">Findings</TabsTrigger>
              <TabsTrigger value="settings">Settings</TabsTrigger>
            </TabsList>
            <TabsContent value="findings">
              <FindingsTab brandId={brand.brand_id} />
            </TabsContent>
            <TabsContent value="settings">
              <SettingsTab brand={brand} onUpdated={setBrand} onDeleted={onBack} />
            </TabsContent>
          </Tabs>
        )}
      </div>
    </div>
  )
}
