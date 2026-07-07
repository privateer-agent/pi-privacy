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
// don't retain data. This turns openrouter's tier from zdr-policy → zdr-enforced.
//
// HONESTY GATE: the enforced tier is only earned if this patch is actually applied
// AND OpenRouter honors the routing key. The exact field is TODO(verify) against
// OpenRouter's current routing schema — until verified live, callers should treat
// OpenRouter as zdr-policy, not zdr-enforced, and this patch as best-effort. We do
// NOT want to badge "enforced" on an unverified param.
export function openRouterZdrPatch(payload: unknown): Record<string, unknown> {
  const p = asObject(payload);
  const provider = p.provider && typeof p.provider === "object"
    ? (p.provider as Record<string, unknown>)
    : {};
  return { ...p, provider: { ...provider, zdr: true } };
}
