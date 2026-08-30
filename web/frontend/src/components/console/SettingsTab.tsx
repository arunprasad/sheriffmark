import { useState } from "react"
import { toast } from "sonner"
import { api, type Brand } from "@/lib/api"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog"
import { DomainListEditor } from "@/components/console/DomainListEditor"
import { ReferenceImagesSection } from "@/components/console/ReferenceImagesSection"

export function SettingsTab({
  brand,
  onUpdated,
  onDeleted,
}: {
  brand: Brand
  onUpdated: (brand: Brand) => void
  onDeleted: () => void
}) {
  const [name, setName] = useState(brand.name)
  const [keywordsText, setKeywordsText] = useState(brand.keywords.join(", "))
  const [tldsText, setTldsText] = useState(brand.tlds.join(", "))
  const [saving, setSaving] = useState(false)

  const dirty =
    name !== brand.name ||
    keywordsText !== brand.keywords.join(", ") ||
    tldsText !== brand.tlds.join(", ")

  async function handleSaveDetails(e: React.FormEvent) {
    e.preventDefault()
    setSaving(true)
    try {
      const updated = await api.updateBrand(brand.brand_id, {
        name,
        keywords: keywordsText.split(",").map((s) => s.trim()).filter(Boolean),
        tlds: tldsText.split(",").map((s) => s.trim()).filter(Boolean),
      })
      onUpdated(updated)
      toast.success("Brand details saved")
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e))
    } finally {
      setSaving(false)
    }
  }

  async function handleToggleActive(active: boolean) {
    try {
      const updated = await api.updateBrand(brand.brand_id, { active })
      onUpdated(updated)
      toast.success(active ? "Scanning resumed" : "Scanning paused")
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e))
    }
  }

  async function handleDelete() {
    try {
      await api.deleteBrand(brand.brand_id)
      toast.success(`${brand.name} deleted`)
      onDeleted()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e))
    }
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Brand details</CardTitle>
          <CardDescription>Display name and what the generator watches for.</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSaveDetails} className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="settings-brand-name">Display name</Label>
              <Input
                id="settings-brand-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                className="max-w-sm"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="settings-brand-keywords">Keywords</Label>
              <Input
                id="settings-brand-keywords"
                value={keywordsText}
                onChange={(e) => setKeywordsText(e.target.value)}
                placeholder="acme, acmecorp"
                className="max-w-sm"
              />
              <p className="text-xs text-muted-foreground">Comma-separated.</p>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="settings-brand-tlds">TLDs</Label>
              <Input
                id="settings-brand-tlds"
                value={tldsText}
                onChange={(e) => setTldsText(e.target.value)}
                placeholder="com, net, org"
                className="max-w-sm"
              />
              <p className="text-xs text-muted-foreground">Comma-separated, no leading dot.</p>
            </div>
            <Button type="submit" size="sm" disabled={saving || !dirty}>
              {saving ? "Saving…" : "Save"}
            </Button>
          </form>

          <div className="mt-6 flex items-center justify-between border-t pt-4">
            <div>
              <Label htmlFor="settings-brand-active">Scanning</Label>
              <p className="text-xs text-muted-foreground">
                Paused brands are skipped by the daily worker entirely.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-sm text-muted-foreground">
                {brand.active ? "Active" : "Paused"}
              </span>
              <Switch
                id="settings-brand-active"
                checked={brand.active}
                onCheckedChange={handleToggleActive}
              />
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Custom domains</CardTitle>
          <CardDescription>
            Exact domains to watch alongside whatever the generator produces.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <DomainListEditor
            domains={brand.custom_domains}
            placeholder="suspicious-lookalike.com"
            onAdd={async (domain) => onUpdated(await api.addCustomDomain(brand.brand_id, domain))}
            onRemove={async (domain) =>
              onUpdated(await api.removeCustomDomain(brand.brand_id, domain))
            }
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Owned domains</CardTitle>
          <CardDescription>
            Domains you legitimately own — seeded into generation, but excluded from findings.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <DomainListEditor
            domains={brand.owned_domains}
            placeholder="acme.com"
            onAdd={async (domain) => onUpdated(await api.addOwnedDomain(brand.brand_id, domain))}
            onRemove={async (domain) =>
              onUpdated(await api.removeOwnedDomain(brand.brand_id, domain))
            }
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Reference images</CardTitle>
          <CardDescription>For logo and site-clone visual similarity detection.</CardDescription>
        </CardHeader>
        <CardContent>
          <ReferenceImagesSection brandId={brand.brand_id} />
        </CardContent>
      </Card>

      <Card className="border-destructive/30">
        <CardHeader>
          <CardTitle className="text-destructive">Danger zone</CardTitle>
          <CardDescription>
            Deletes this brand and every finding/incident recorded under it. Cannot be undone.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <AlertDialog>
            <AlertDialogTrigger render={<Button variant="destructive" />}>
              Delete brand
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>Delete {brand.name}?</AlertDialogTitle>
                <AlertDialogDescription>
                  This permanently deletes the brand and all of its findings and incident
                  history. This cannot be undone.
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                <AlertDialogAction
                  className="bg-destructive text-destructive-foreground hover:bg-destructive/80"
                  onClick={handleDelete}
                >
                  Delete
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </CardContent>
      </Card>
    </div>
  )
}
