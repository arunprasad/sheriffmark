// Client-side session storage for whichever auth provider issued the
// token — local email/password, or SAML (which redirects back with the
// token in the URL fragment; see App.tsx). All providers produce the
// same self-issued JWT shape (web/api/session_tokens.py), so the
// frontend doesn't need to know or care which one was used.

const STORAGE_KEY = "sheriffmark_token"

export type SessionUser = {
  sub: string
  email: string | null
}

function decodeJwtPayload(token: string): SessionUser | null {
  try {
    const [, payload] = token.split(".")
    const json = atob(payload.replace(/-/g, "+").replace(/_/g, "/"))
    const claims = JSON.parse(json)
    return { sub: claims.sub, email: claims.email ?? null }
  } catch {
    return null
  }
}

function isExpired(token: string): boolean {
  try {
    const [, payload] = token.split(".")
    const claims = JSON.parse(atob(payload.replace(/-/g, "+").replace(/_/g, "/")))
    if (typeof claims.exp !== "number") return false
    return Date.now() >= claims.exp * 1000
  } catch {
    return true
  }
}

export const authClient = {
  getToken(): string | null {
    const token = localStorage.getItem(STORAGE_KEY)
    if (!token) return null
    if (isExpired(token)) {
      localStorage.removeItem(STORAGE_KEY)
      return null
    }
    return token
  },

  getUser(): SessionUser | null {
    const token = authClient.getToken()
    return token ? decodeJwtPayload(token) : null
  },

  setToken(token: string) {
    localStorage.setItem(STORAGE_KEY, token)
  },

  clear() {
    localStorage.removeItem(STORAGE_KEY)
  },
}
