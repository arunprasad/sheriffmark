import { useEffect, useState } from "react"
import { toast } from "sonner"
import { api, type Account } from "@/lib/api"
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
import { SettingsIcon } from "lucide-react"

const CHANNEL_FIELDS: { key: string; label: string; placeholder: string }[] = [
  { key: "slack_webhook_url", label: "Slack webhook", placeholder: "https://hooks.slack.com/…" },
  { key: "discord_webhook_url", label: "Discord webhook", placeholder: "https://discord.com/api/webhooks/…" },
  { key: "webhook_url", label: "Generic webhook", placeholder: "https://example.com/hooks/sheriffmark" },
]

export function AccountSettingsDialog() {
  const [open, setOpen] = useState(false)
  const [account, setAccount] = useState<Account | null>(null)
  const [contactEmail, setContactEmail] = useState("")
  const [channels, setChannels] = useState<Record<string, string>>({})
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (!open) return
    api.getAccount().then((a) => {
      setAccount(a)
      setContactEmail(a.contact_email ?? "")
      setChannels(a.notification_channels)
    })
  }, [open])

  async function handleSave(e: React.FormEvent) {
    e.preventDefault()
    setSaving(true)
    try {
      const updated = await api.updateAccount({
        contact_email: contactEmail || null,
        notification_channels: channels,
      })
      setAccount(updated)
      toast.success("Account settings saved")
      setOpen(false)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e))
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger render={<Button variant="outline" />}>
        <SettingsIcon />
        Account
      </DialogTrigger>
      <DialogContent className="sm:max-w-md">
        <form onSubmit={handleSave}>
          <DialogHeader>
            <DialogTitle>Account settings</DialogTitle>
            <DialogDescription>
              {account ? account.name : "Loading…"} — shared across every brand on this account.
            </DialogDescription>
          </DialogHeader>

          {account && (
            <div className="mt-4 space-y-4">
              <div className="space-y-1.5">
                <Label htmlFor="account-contact-email">Contact email</Label>
                <Input
                  id="account-contact-email"
                  type="email"
                  placeholder="ops@acme.com"
                  value={contactEmail}
                  onChange={(e) => setContactEmail(e.target.value)}
                />
              </div>

              <div className="space-y-3">
                <Label>Notification channels</Label>
                {CHANNEL_FIELDS.map((field) => (
                  <div key={field.key} className="space-y-1">
                    <Label htmlFor={`channel-${field.key}`} className="text-xs font-normal text-muted-foreground">
                      {field.label}
                    </Label>
                    <Input
                      id={`channel-${field.key}`}
                      placeholder={field.placeholder}
                      value={channels[field.key] ?? ""}
                      onChange={(e) =>
                        setChannels((prev) => ({ ...prev, [field.key]: e.target.value }))
                      }
                    />
                  </div>
                ))}
              </div>
            </div>
          )}

          <DialogFooter className="mt-4">
            <Button type="submit" disabled={saving || !account}>
              {saving ? "Saving…" : "Save"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
