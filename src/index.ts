// Public API for the pi-privacy package (working name).
//
// Two things a consumer wants: (1) the honest privacy taxonomy — tiers + provider
// catalog — and (2) [coming next] the Pi extension that registers these providers,
// installs the attestation dispatcher, verifies TEE posture, and enforces/labels
// ZDR. This turn ships (1) + the catalog; the attestation engine + extension land
// next (ported from privateer 0.2 attestation.ts).

export {
  type PrivacyTier,
  type Verifiability,
  type TierInfo,
  TIERS,
  tierRank,
  tierFromTeePosture,
} from "./posture/tiers.ts";

export {
  type ProviderApi,
  type PrivacyProvider,
  PRIVACY_PROVIDERS,
  PROVIDER_BY_ID,
  isLocalEndpoint,
} from "./providers/catalog.ts";

// Resolve a provider's effective tier, accounting for on-device detection and
// posture-aware providers. `zdrEnforced` reflects whether ZDR routing is actively
// pinned this session (OpenRouter). Kept here so both the badge layer and the
// picker sort share one honest source of truth.
import { PROVIDER_BY_ID, isLocalEndpoint } from "./providers/catalog.ts";
import type { PrivacyTier } from "./posture/tiers.ts";

export function effectiveTier(
  providerId: string,
  opts: { baseUrl?: string; zdrEnforced?: boolean } = {},
): PrivacyTier {
  const p = PROVIDER_BY_ID[providerId];
  if (!p) return "standard";
  // On-device beats a claimed policy tier: a loopback endpoint is observable.
  if (p.local || isLocalEndpoint(opts.baseUrl)) return "local";
  // OpenRouter: zdr-policy until routing is enforced, then zdr-enforced.
  if (p.postureAware && p.id === "openrouter") {
    return opts.zdrEnforced ? "zdr-enforced" : "zdr-policy";
  }
  // TEE providers advertise their ceiling; the actual green/yellow verdict comes
  // from the attestation engine at runtime (tierFromTeePosture). This is the
  // pre-attestation default.
  return p.tier;
}
