import { useEffect, useState } from "react"
import { authClient, type SessionUser } from "@/lib/authClient"

// A SAML login redirects the browser back here with the freshly-issued
// token in the URL fragment (never sent to any server) — see
// web/api/saml_auth.py's handle_acs. Pick it up once, on first load,
// before anything else reads auth state.
function consumeFragmentToken() {
  const hash = window.location.hash
  if (!hash.includes("token=")) return
  const params = new URLSearchParams(hash.replace(/^#/, ""))
  const token = params.get("token")
  if (token) {
    authClient.setToken(token)
    history.replaceState(null, "", window.location.pathname + window.location.search)
  }
}

export function useAuth() {
  const [user, setUser] = useState<SessionUser | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    consumeFragmentToken()
    setUser(authClient.getUser())
    setLoading(false)
  }, [])

  return {
    user,
    loading,
    signedIn: user !== null,
    setSignedIn: (token: string) => {
      authClient.setToken(token)
      setUser(authClient.getUser())
    },
    signOut: () => {
      authClient.clear()
      setUser(null)
    },
  }
}
