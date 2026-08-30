import { useState } from "react"
import { toast } from "sonner"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { XIcon } from "lucide-react"

/** Shared add/remove-one-domain-at-a-time editor behind both the
 * custom-domains and owned-domains settings sections — same shape,
 * different storage endpoints on the brand. */
export function DomainListEditor({
  domains,
  onAdd,
  onRemove,
  placeholder,
}: {
  domains: string[]
  onAdd: (domain: string) => Promise<void>
  onRemove: (domain: string) => Promise<void>
  placeholder: string
}) {
  const [value, setValue] = useState("")
  const [submitting, setSubmitting] = useState(false)
  const [removing, setRemoving] = useState<string | null>(null)

  async function handleAdd(e: React.FormEvent) {
    e.preventDefault()
    if (!value.trim()) return
    setSubmitting(true)
    try {
      await onAdd(value.trim().toLowerCase())
      setValue("")
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e))
    } finally {
      setSubmitting(false)
    }
  }

  async function handleRemove(domain: string) {
    setRemoving(domain)
    try {
      await onRemove(domain)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e))
    } finally {
      setRemoving(null)
    }
  }

  return (
    <div className="space-y-3">
      <form onSubmit={handleAdd} className="flex gap-2">
        <Input
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder={placeholder}
          className="max-w-xs"
        />
        <Button type="submit" size="sm" variant="outline" disabled={submitting}>
          Add
        </Button>
      </form>
      <div className="flex flex-wrap gap-2">
        {domains.length === 0 && <p className="text-sm text-muted-foreground">None yet.</p>}
        {domains.map((domain) => (
          <Badge key={domain} variant="secondary" className="gap-1 pr-1 font-mono">
            {domain}
            <button
              type="button"
              onClick={() => handleRemove(domain)}
              disabled={removing === domain}
              className="ml-0.5 rounded-full p-0.5 hover:bg-foreground/10"
              aria-label={`Remove ${domain}`}
            >
              <XIcon className="size-3" />
            </button>
          </Badge>
        ))}
      </div>
    </div>
  )
}
