import { useEffect, useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { api, ApiError, type AuthProviders } from "@/lib/api"

type Mode = "login" | "register"

function errorMessage(e: unknown): string {
  if (e instanceof ApiError) {
    try {
      const body = JSON.parse(e.message) as { detail?: string }
      if (body.detail) return body.detail
    } catch {
      // not JSON — fall through to the raw message
    }
  }
  return e instanceof Error ? e.message : String(e)
}

export function Login({ onSignedIn }: { onSignedIn: (token: string) => void }) {
  const [providers, setProviders] = useState<AuthProviders | null>(null)
  const [mode, setMode] = useState<Mode>("login")
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [verificationPending, setVerificationPending] = useState(false)

  useEffect(() => {
    api
      .authProviders()
      .then(setProviders)
      .catch((e) => setError(errorMessage(e)))
  }, [])

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setSubmitting(true)
    setError(null)
    try {
      const result = mode === "login" ? await api.login(email, password) : await api.register(email, password)
      if (result.email_verification_required) {
        setVerificationPending(true)
      } else {
        onSignedIn(result.access_token)
      }
    } catch (e) {
      setError(errorMessage(e))
    } finally {
      setSubmitting(false)
    }
  }

  const noProvidersEnabled = providers && !providers.local && !providers.saml

  return (
    <div className="flex min-h-screen items-center justify-center bg-muted/40">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle>SheriffMark</CardTitle>
          <CardDescription>
            {verificationPending
              ? "Check your email for a verification link, then sign in."
              : mode === "login"
                ? "Sign in to your account."
                : "Create an account."}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {noProvidersEnabled && (
            <p className="text-sm text-destructive">
              No auth providers are enabled on this server. Set AUTH_ENABLE_LOCAL, _OIDC, or _SAML.
            </p>
          )}

          {!verificationPending && providers?.local && (
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="email">Email</Label>
                <Input
                  id="email"
                  type="email"
                  placeholder="you@company.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  type="password"
                  placeholder={mode === "register" ? "At least 8 characters" : "••••••••"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  minLength={8}
                  required
                />
              </div>
              {error && <p className="text-sm text-destructive">{error}</p>}
              <Button type="submit" className="w-full" disabled={submitting}>
                {submitting ? "Please wait…" : mode === "login" ? "Sign in" : "Create account"}
              </Button>
              <button
                type="button"
                className="w-full text-center text-sm text-muted-foreground underline-offset-2 hover:underline"
                onClick={() => {
                  setMode(mode === "login" ? "register" : "login")
                  setError(null)
                }}
              >
                {mode === "login" ? "Need an account? Register" : "Already have an account? Sign in"}
              </button>
            </form>
          )}

          {!verificationPending && providers?.saml && (
            <>
              {providers.local && (
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <div className="h-px flex-1 bg-border" />
                  or
                  <div className="h-px flex-1 bg-border" />
                </div>
              )}
              <Button
                variant="outline"
                className="w-full"
                onClick={() => {
                  const base = import.meta.env.VITE_API_BASE_URL || ""
                  window.location.href = `${base}/api/auth/saml/login`
                }}
              >
                Sign in with SSO
              </Button>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
