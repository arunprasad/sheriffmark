import { useEffect, useState } from "react"

export type Route = { view: "index" } | { view: "brand"; brandId: string }

function parseHash(): Route {
  const hash = window.location.hash.replace(/^#\/?/, "")
  const match = hash.match(/^brands\/([^/]+)/)
  if (match) return { view: "brand", brandId: match[1] }
  return { view: "index" }
}

/** Minimal hash router — just enough for back/forward and bookmarkable
 * brand-console URLs without pulling in a routing library for two
 * views. Not used for the SAML fragment-token exchange (useAuth
 * clears that hash before this ever mounts — see App.tsx). */
export function useHashRoute() {
  const [route, setRoute] = useState<Route>(parseHash)

  useEffect(() => {
    const onHashChange = () => setRoute(parseHash())
    window.addEventListener("hashchange", onHashChange)
    return () => window.removeEventListener("hashchange", onHashChange)
  }, [])

  function navigate(next: Route) {
    window.location.hash = next.view === "brand" ? `/brands/${next.brandId}` : "/"
  }

  return { route, navigate }
}
