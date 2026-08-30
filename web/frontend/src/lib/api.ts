import { authClient } from "@/lib/authClient"

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || ""

export type Brand = {
  brand_id: string
  name: string
  keywords: string[]
  tlds: string[]
  active: boolean
  custom_domains: string[]
  owned_domains: string[]
  last_scan_completed_at: string | null
  unresolved_findings_count: number
}

export type ResolutionStatus = "open" | "resolved" | "resolved_owned" | "resolution_failed"

export type Finding = {
  domain: string
  brand_id: string
  source: "generated" | "ct" | "manual" | "on_demand"
  status: string
  registrar: string | null
  created_date: string | null
  abuse_email: string | null
  risk_score: number | null
  risk_factors: string[]
  first_seen: string
  last_checked: string
  resolution_status: ResolutionStatus
  resolution_note: string | null
}

export type IncidentEventType =
  | "registered"
  | "whois_change"
  | "dns_change"
  | "ip_blocklisted"
  | "website_change"
  | "form_detected"
  | "redirect_detected"
  | "spa_detected"
  | "logo_match_detected"
  | "site_clone_detected"
  | "resolved"
  | "resolved_owned"
  | "resolution_failed"
  | "reopened"

export type Incident = {
  event_type: IncidentEventType
  detected_at: string
  details: Record<string, unknown>
}

export type Account = {
  tenant_id: string
  name: string
  contact_email: string | null
  notification_channels: Record<string, string>
}

export type ReferenceImage = {
  id: string
  kind: "logo" | "site_screenshot"
  filename: string | null
  content_type: string
  created_at: string
}

class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

/** Network-level failures (connection refused, DNS failure, offline) surface
 * from `fetch` as a bare `TypeError: Failed to fetch` — accurate for a
 * browser console, meaningless to someone looking at the console UI. Give
 * those a message that actually points at the fix. HTTP-level failures
 * (4xx/5xx, a real response came back) are left to the caller as-is. */
function describeNetworkError(e: unknown): ApiError {
  const detail = e instanceof Error ? e.message : String(e)
  return new ApiError(
    0,
    `Could not reach the server at ${API_BASE_URL || "this origin"}. ` +
      `Is the backend running? (${detail})`,
  )
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = authClient.getToken()

  let resp: Response
  try {
    resp = await fetch(`${API_BASE_URL}${path}`, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...options.headers,
      },
    })
  } catch (e) {
    throw describeNetworkError(e)
  }

  if (!resp.ok) {
    const body = await resp.text()
    throw new ApiError(resp.status, body || resp.statusText)
  }
  if (resp.status === 204) return undefined as T
  return resp.json() as Promise<T>
}

/** For endpoints that return a binary body (screenshots, reference
 * images, the CSV export) and are behind the same tenant auth as
 * everything else — a plain `<img src>`/`<a href>` can't carry the
 * Authorization header, so these fetch and hand back an object URL
 * the caller is responsible for revoking (`URL.revokeObjectURL`). */
async function requestBlob(path: string): Promise<{ blob: Blob; filename: string | null }> {
  const token = authClient.getToken()
  let resp: Response
  try {
    resp = await fetch(`${API_BASE_URL}${path}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : undefined,
    })
  } catch (e) {
    throw describeNetworkError(e)
  }
  if (!resp.ok) {
    throw new ApiError(resp.status, (await resp.text()) || resp.statusText)
  }
  const disposition = resp.headers.get("Content-Disposition")
  const match = disposition?.match(/filename="?([^"]+)"?/)
  return { blob: await resp.blob(), filename: match ? match[1] : null }
}

export type AuthProviders = {
  local: boolean
  oidc: boolean
  saml: boolean
  local_requires_verification: boolean
}

export type AuthTokenResponse = {
  access_token: string
  token_type: string
  email_verification_required: boolean
}

export const api = {
  authProviders: () => request<AuthProviders>("/api/auth/providers"),
  register: (email: string, password: string) =>
    request<AuthTokenResponse>("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),
  login: (email: string, password: string) =>
    request<AuthTokenResponse>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),
  listBrands: () => request<Brand[]>("/api/brands"),
  createBrand: (input: { name: string; keywords: string[]; tlds: string[] }) =>
    request<Brand>("/api/brands", { method: "POST", body: JSON.stringify(input) }),
  updateBrand: (
    brandId: string,
    input: Partial<{ name: string; keywords: string[]; tlds: string[]; active: boolean }>,
  ) =>
    request<Brand>(`/api/brands/${brandId}`, { method: "PATCH", body: JSON.stringify(input) }),
  deleteBrand: (brandId: string) =>
    request<void>(`/api/brands/${brandId}`, { method: "DELETE" }),

  addCustomDomain: (brandId: string, domain: string) =>
    request<Brand>(`/api/brands/${brandId}/custom-domains`, {
      method: "POST",
      body: JSON.stringify({ domain }),
    }),
  removeCustomDomain: (brandId: string, domain: string) =>
    request<Brand>(`/api/brands/${brandId}/custom-domains/${encodeURIComponent(domain)}`, {
      method: "DELETE",
    }),
  addOwnedDomain: (brandId: string, domain: string) =>
    request<Brand>(`/api/brands/${brandId}/owned-domains`, {
      method: "POST",
      body: JSON.stringify({ domain }),
    }),
  removeOwnedDomain: (brandId: string, domain: string) =>
    request<Brand>(`/api/brands/${brandId}/owned-domains/${encodeURIComponent(domain)}`, {
      method: "DELETE",
    }),

  listFindings: (brandId?: string, filters?: { status?: string; resolution_status?: string }) => {
    const params = new URLSearchParams()
    if (brandId) params.set("brand_id", brandId)
    if (filters?.status) params.set("status", filters.status)
    if (filters?.resolution_status) params.set("resolution_status", filters.resolution_status)
    const qs = params.toString()
    return request<Finding[]>(`/api/findings${qs ? `?${qs}` : ""}`)
  },
  exportFindingsCsv: (brandId?: string) =>
    requestBlob(`/api/findings/export.csv${brandId ? `?brand_id=${brandId}` : ""}`),
  listFindingIncidents: (domain: string, brandId: string) =>
    request<Incident[]>(
      `/api/findings/${encodeURIComponent(domain)}/incidents?brand_id=${brandId}`,
    ),
  resolveFinding: (
    domain: string,
    brandId: string,
    input: { status: ResolutionStatus; note?: string | null },
  ) =>
    request<Finding>(
      `/api/findings/${encodeURIComponent(domain)}/resolution?brand_id=${brandId}`,
      { method: "POST", body: JSON.stringify(input) },
    ),
  findingScreenshot: (domain: string, brandId: string) =>
    requestBlob(`/api/findings/${encodeURIComponent(domain)}/screenshot?brand_id=${brandId}`),
  findingReportPdf: (domain: string, brandId: string) =>
    requestBlob(`/api/findings/${encodeURIComponent(domain)}/report.pdf?brand_id=${brandId}`),

  getAccount: () => request<Account>("/api/account"),
  updateAccount: (input: { contact_email?: string | null; notification_channels?: Record<string, string> }) =>
    request<Account>("/api/account", { method: "PATCH", body: JSON.stringify(input) }),

  listReferenceImages: (brandId: string) =>
    request<ReferenceImage[]>(`/api/brands/${brandId}/reference-images`),
  uploadReferenceImage: async (
    brandId: string,
    kind: "logo" | "site_screenshot",
    file: File,
  ) => {
    const token = authClient.getToken()
    const form = new FormData()
    form.set("kind", kind)
    form.set("file", file)
    let resp: Response
    try {
      resp = await fetch(`${API_BASE_URL}/api/brands/${brandId}/reference-images`, {
        method: "POST",
        headers: token ? { Authorization: `Bearer ${token}` } : undefined,
        body: form,
      })
    } catch (e) {
      throw describeNetworkError(e)
    }
    if (!resp.ok) throw new ApiError(resp.status, (await resp.text()) || resp.statusText)
    return resp.json() as Promise<ReferenceImage>
  },
  deleteReferenceImage: (brandId: string, imageId: string) =>
    request<void>(`/api/brands/${brandId}/reference-images/${imageId}`, { method: "DELETE" }),
  getReferenceImage: (brandId: string, imageId: string) =>
    requestBlob(`/api/brands/${brandId}/reference-images/${imageId}`),
}

export { ApiError }
