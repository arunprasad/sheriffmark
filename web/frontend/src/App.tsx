import { useAuth } from "@/hooks/useAuth"
import { useHashRoute } from "@/hooks/useHashRoute"
import { Login } from "@/pages/Login"
import { BrandIndex } from "@/pages/BrandIndex"
import { BrandConsole } from "@/pages/BrandConsole"

function App() {
  const { signedIn, loading, setSignedIn, signOut } = useAuth()
  const { route, navigate } = useHashRoute()

  if (loading) {
    return <div className="flex min-h-screen items-center justify-center text-muted-foreground">Loading…</div>
  }

  if (!signedIn) {
    return <Login onSignedIn={setSignedIn} />
  }

  if (route.view === "brand") {
    return (
      <BrandConsole
        brandId={route.brandId}
        onBack={() => navigate({ view: "index" })}
        onSignOut={signOut}
      />
    )
  }

  return (
    <BrandIndex onOpenBrand={(brandId) => navigate({ view: "brand", brandId })} onSignOut={signOut} />
  )
}

export default App
