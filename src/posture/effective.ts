import { PROVIDER_BY_ID, isLocalEndpoint } from "../providers/catalog.ts";
import type { PrivacyTier } from "./tiers.ts";

// Resolve a provider's effective tier, accounting for on-device detection and
// posture-aware providers. `zdrEnforced` reflects whether ZDR routing is actively
// pinned this session (OpenRouter). The one honest source of truth shared by the
// badge layer, the picker sort, and posture verification.
//
// NOTE: for TEE providers this returns only the pre-attestation CEILING
// (tee-verified as an advertised capability). The real green/yellow/red verdict
// comes from verifyModelPosture() at runtime — never claim tee-verified from this
// function alone.
export function effectiveTier(
  providerId: string,
  opts: { baseUrl?: string; zdrEnforced?: boolean; verifiedTee?: boolean } = {},
): PrivacyTier {
  const p = PROVIDER_BY_ID[providerId];
  if (!p) return "standard";
  if (p.local || isLocalEndpoint(opts.baseUrl)) return "local";
  if (p.postureAware && p.id === "openrouter") {
    return opts.zdrEnforced ? "zdr-enforced" : "zdr-policy";
  }
  // Privateer: the tee-verified ceiling is reachable ONLY through the in-app account
  // channel. The public developer key (sk-priv-…) is server-proxied — the proxy
  // mediates attestation, so we can't verify the enclave end-to-end — and floors to
  // zdr-policy. Never claim tee-verified from the public key alone.
  if (p.postureAware && p.id === "privateer") {
    return opts.verifiedTee ? "tee-verified" : "zdr-policy";
  }
  return p.tier;
}
