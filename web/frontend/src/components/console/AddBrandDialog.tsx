import { useState } from "react"
import { toast } from "sonner"
import { api, ApiError, type Brand } from "@/lib/api"
import { splitDomain } from "@/lib/domain"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { PlusIcon } from "lucide-react"

// A handful of common extensions to also watch by default, on top of
// whatever TLDs actually show up in the owned domains typed in —
// keeps the minimal form minimal while still giving the generator
// something to work with beyond the exact TLD(s) the user already
// owns.
const DEFAULT_TLDS = ["com", "net", "org"]

export function AddBrandDialog({ onCreated }: { onCreated: (brand: Brand) => void }) {
  const [open, setOpen] = useState(false)
  const [name, setName] = useState("")
  const [ownedDomainsText, setOwnedDomainsText] = useState("")
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  function reset() {
    setName("")
    setOwnedDomainsText("")
    setError(null)
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setSubmitting(true)
    try {
      const ownedDomains = ownedDomainsText
        .split(/[\n,]/)
        .map((d) => d.trim().toLowerCase())
        .filter(Boolean)

      const split = ownedDomains.map(splitDomain)
      const keywords = [...new Set(split.map((s) => s.sld).filter(Boolean))]
      const tlds = [...new Set([...DEFAULT_TLDS, ...split.map((s) => s.tld).filter(Boolean)])]

      const brand = await api.createBrand({ name, keywords, tlds })

      for (const domain of ownedDomains) {
        await api.addOwnedDomain(brand.brand_id, domain)
      }

      toast.success(`${brand.name} added`)
      setOpen(false)
      reset()
      onCreated({ ...brand, owned_domains: ownedDomains })
    } catch (e) {
      if (e instanceof ApiError && e.status === 402) {
        setError("Brand limit reached for your plan — upgrade to add more.")
      } else {
        setError(e instanceof Error ? e.message : String(e))
      }
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next)
        if (!next) reset()
      }}
    >
      <DialogTrigger render={<Button />}>
        <PlusIcon />
        Add brand
      </DialogTrigger>
      <DialogContent className="sm:max-w-md">
        <form onSubmit={handleSubmit}>
          <DialogHeader>
            <DialogTitle>Add a brand</DialogTitle>
            <DialogDescription>
              A display name and the domains you already own is enough to start — SheriffMark
              uses the owned domains' names as keywords and extensions to watch for lookalikes.
            </DialogDescription>
          </DialogHeader>

          <div className="mt-4 space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="new-brand-name">Display name</Label>
              <Input
                id="new-brand-name"
                placeholder="Acme Corp"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                autoFocus
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="new-brand-owned-domains">Owned domains</Label>
              <Textarea
                id="new-brand-owned-domains"
                placeholder={"acme.com\nacme.net"}
                value={ownedDomainsText}
                onChange={(e) => setOwnedDomainsText(e.target.value)}
                rows={3}
              />
              <p className="text-xs text-muted-foreground">
                One per line (or comma-separated). Optional, but recommended.
              </p>
            </div>
          </div>

          {error && (
            <p className="mt-4 text-sm text-destructive" role="alert">
              {error}
            </p>
          )}

          <DialogFooter className="mt-4">
            <Button type="submit" disabled={submitting}>
              {submitting ? "Adding…" : "Add brand"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
