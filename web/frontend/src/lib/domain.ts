/** Naive domain split used only for pre-filling a new brand's keyword
 * and TLD from an owned domain the user typed in (e.g. "acme.com" ->
 * sld "acme", tld "com"). Doesn't try to handle multi-part public
 * suffixes (co.uk) correctly — it's a starting point the user can
 * still edit before saving, not a validator. */
export function splitDomain(domain: string): { sld: string; tld: string } {
  const parts = domain.trim().toLowerCase().split(".")
  return { sld: parts[0] ?? "", tld: parts.slice(1).join(".") }
}
