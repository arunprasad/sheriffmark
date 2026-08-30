import { useEffect, useRef, useState } from "react"
import { toast } from "sonner"
import { api, type ReferenceImage } from "@/lib/api"
import { useAuthedBlobUrl } from "@/hooks/useAuthedBlobUrl"
import { Button } from "@/components/ui/button"
import { Label } from "@/components/ui/label"
import { TrashIcon, UploadIcon } from "lucide-react"

function ReferenceImageThumbnail({ brandId, image }: { brandId: string; image: ReferenceImage }) {
  const { url } = useAuthedBlobUrl(`${brandId}:${image.id}`, () =>
    api.getReferenceImage(brandId, image.id),
  )
  return url ? (
    <img
      src={url}
      alt={image.filename ?? image.kind}
      className="size-20 rounded-md border object-cover"
    />
  ) : (
    <div className="size-20 animate-pulse rounded-md border bg-muted" />
  )
}

function ReferenceImageKindSection({
  brandId,
  kind,
  title,
  hint,
}: {
  brandId: string
  kind: "logo" | "site_screenshot"
  title: string
  hint: string
}) {
  const [images, setImages] = useState<ReferenceImage[]>([])
  const [loading, setLoading] = useState(true)
  const [uploading, setUploading] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  function reload() {
    setLoading(true)
    api
      .listReferenceImages(brandId)
      .then((all) => setImages(all.filter((img) => img.kind === kind)))
      .catch((e) => toast.error(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false))
  }

  useEffect(reload, [brandId, kind])

  async function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    e.target.value = ""
    if (!file) return
    setUploading(true)
    try {
      await api.uploadReferenceImage(brandId, kind, file)
      reload()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e))
    } finally {
      setUploading(false)
    }
  }

  async function handleDelete(imageId: string) {
    try {
      await api.deleteReferenceImage(brandId, imageId)
      setImages((prev) => prev.filter((img) => img.id !== imageId))
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e))
    }
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <div>
          <Label className="text-sm font-normal">{title}</Label>
          <p className="text-xs text-muted-foreground">{hint}</p>
        </div>
        <Button
          type="button"
          size="sm"
          variant="outline"
          disabled={uploading}
          onClick={() => fileInputRef.current?.click()}
        >
          <UploadIcon />
          {uploading ? "Uploading…" : "Upload"}
        </Button>
        <input
          ref={fileInputRef}
          type="file"
          accept="image/png,image/jpeg,image/webp"
          className="hidden"
          onChange={handleFileChange}
        />
      </div>

      {loading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : images.length === 0 ? (
        <p className="text-sm text-muted-foreground">None uploaded yet.</p>
      ) : (
        <div className="flex flex-wrap gap-3">
          {images.map((img) => (
            <div key={img.id} className="relative">
              <ReferenceImageThumbnail brandId={brandId} image={img} />
              <button
                type="button"
                onClick={() => handleDelete(img.id)}
                className="absolute -top-1.5 -right-1.5 rounded-full border bg-background p-1 text-muted-foreground hover:text-destructive"
                aria-label="Delete image"
              >
                <TrashIcon className="size-3" />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

/** Reference images feed visual-similarity detection
 * (core/visual_similarity.py) — a logo to match against pages found
 * on flagged domains, and a screenshot of the real site to catch
 * outright clones. */
export function ReferenceImagesSection({ brandId }: { brandId: string }) {
  return (
    <div className="space-y-6">
      <ReferenceImageKindSection
        brandId={brandId}
        kind="logo"
        title="Logo"
        hint="Matched against pages found on flagged domains."
      />
      <ReferenceImageKindSection
        brandId={brandId}
        kind="site_screenshot"
        title="Site screenshot"
        hint="Compared against flagged domains to catch outright clones."
      />
    </div>
  )
}
