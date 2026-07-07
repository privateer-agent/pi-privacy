// Pure `before_provider_request` payload transforms. Kept separate so they're unit
// -testable without a live session; the extension wires them per current provider.

function asObject(payload: unknown): Record<string, unknown> {
  return payload && typeof payload === "object" ? { ...(payload as Record<string, unknown>) } : {};
}

// Venice: disable Venice's injected system prompt by setting
// venice_parameters.include_venice_system_prompt = false on the request body.
// This is the code-blocker from the migration plan (Appendix A) — no models.json
// equivalent exists, so it's a request-body patch. Returns a NEW payload.
export function veniceRequestPatch(payload: unknown): Record<string, unknown> {
  const p = asObject(payload);
  const vp = p.venice_parameters && typeof p.venice_parameters === "object"
    ? (p.venice_parameters as Record<string, unknown>)
    : {};
  return { ...p, venice_parameters: { ...vp, include_venice_system_prompt: false } };
}

// OpenRouter: pin ZERO-DATA-RETENTION routing so requests only reach endpoints that
// don't retain data. Turns openrouter's tier from zdr-policy → zdr-enforced.
//
// VERIFIED LIVE (2026-07-07): OpenRouter honors `provider.data_collection: "deny"`
// and `provider.zdr: true` — it filters routing to compliant providers and returns
// 404 "No allowed providers are available" when the policy can't be satisfied
// (i.e. it does NOT silently ignore the constraint). Mirrors pi-ai's native
// OpenRouterRouting (`compat.openRouterRouting`), so the request body is identical
// whether it comes from here or pi-ai. This is enforcement (observable routing),
// NOT attestation — the zdr-enforced tier says so.
export function openRouterZdrPatch(payload: unknown): Record<string, unknown> {
  const p = asObject(payload);
  const provider = p.provider && typeof p.provider === "object"
    ? (p.provider as Record<string, unknown>)
    : {};
  return { ...p, provider: { ...provider, zdr: true, data_collection: "deny" } };
}
