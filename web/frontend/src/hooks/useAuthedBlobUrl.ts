import { useEffect, useRef, useState } from "react"
import { ApiError } from "@/lib/api"

/** Fetches an authenticated binary endpoint (screenshots, reference
 * images) and hands back a blob: object URL, since a plain <img src>
 * can't carry the Authorization header these endpoints require.
 * Re-fetches only when `key` changes (not on every render, since a
 * fresh `fetcher` closure is expected each render); revokes the
 * previous object URL on refetch and on unmount. Pass `key: null` to
 * skip fetching entirely. */
export function useAuthedBlobUrl(
  key: string | null,
  fetcher: () => Promise<{ blob: Blob }>,
): { url: string | null; loading: boolean; notFound: boolean } {
  const [url, setUrl] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [notFound, setNotFound] = useState(false)
  const fetcherRef = useRef(fetcher)
  fetcherRef.current = fetcher

  useEffect(() => {
    if (!key) {
      setUrl(null)
      setNotFound(false)
      return
    }
    let cancelled = false
    let objectUrl: string | null = null
    setLoading(true)
    setNotFound(false)
    fetcherRef
      .current()
      .then(({ blob }) => {
        if (cancelled) return
        objectUrl = URL.createObjectURL(blob)
        setUrl(objectUrl)
      })
      .catch((e) => {
        if (cancelled) return
        if (e instanceof ApiError && e.status === 404) {
          setNotFound(true)
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
      if (objectUrl) URL.revokeObjectURL(objectUrl)
    }
  }, [key])

  return { url, loading, notFound }
}
