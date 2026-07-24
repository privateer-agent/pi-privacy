// The privacy-ranked model picker — pure, testable half.
//
// The badge and /verify REACT to a model the user already chose. This is the other
// direction: help them CHOOSE privacy up front, by ranking the models they can
// actually use with the strongest privacy first, each labeled with what it can offer.
//
// The honesty discipline carries straight over. Ranking a model uses its CAPABILITY
// (ceiling) tier — computing a live attestation for every row would be far too slow
// for a picker, and would send a probe to every TEE provider just to draw a list. So
// a TEE-attestable provider is shown as "Verifiable TEE" (a capability), NEVER the
// live green "Verified TEE" — that word is reserved for a badge that an attestation
// actually produced. The moment the user picks a verifiable-TEE model, the normal
// model_select → verifyModelPosture path runs and the badge shows the real verdict.

import { PROVIDER_BY_ID, isLocalEndpoint } from "../providers/catalog.ts";
import { effectiveTier } from "./effective.ts";
import { type PrivacyTier, tierRank } from "./tiers.ts";

// The subset of a Pi Model we need to rank it. Structural, so it accepts a full
// Model<Api> as well as a bare {provider,id}.
export interface PickerModel {
  provider?: string;
  id?: string;
  name?: string;
  baseUrl?: string;
}

export interface PickerEntry {
  model: PickerModel;
  // The best tier this model can offer (ceiling) — what it's ranked by. NOT a live
  // attestation result.
  capabilityTier: PrivacyTier;
  rank: number;
  glyph: string;
  // Honest capability label. "Verifiable TEE" (not "Verified") for attestable
  // providers, since nothing has been attested yet.
  label: string;
  // True when picking this model triggers a real attestation (tinfoil/nearai).
  attestable: boolean;
}

// The capability (ceiling) tier for a model, WITHOUT running attestation. Loopback is
// checked first so an unknown provider served from localhost is still correctly
// on-device (effectiveTier only loopback-checks providers it knows).
export function capabilityTier(
  providerId: string | undefined,
  baseUrl: string | undefined,
  opts: { zdrEnforced?: boolean } = {},
): PrivacyTier {
  if (isLocalEndpoint(baseUrl)) return "local";
  return effectiveTier(providerId ?? "", { baseUrl, zdrEnforced: opts.zdrEnforced });
}

// Picker glyph + label for a capability tier. Deliberately distinct from the live
// status badge (postureBadge): here ◆ marks a TEE capability that VERIFIES ON SELECT,
// so it never reads as the solid-shield live-verified state.
function capabilityBadge(tier: PrivacyTier, attestable: boolean): { glyph: string; label: string } {
  switch (tier) {
    case "tee-verified":
      // Only reachable as a capability via an attestable provider. The hollow ◆ +
      // the word "Verifiable" (not "Verified") keep it honestly pre-attestation.
      return attestable
        ? { glyph: "◆", label: "Verifiable TEE" }
        : { glyph: "🛡", label: "Verified TEE" };
    case "local":
      return { glyph: "🛡", label: "On-device" };
    case "zdr-enforced":
      return { glyph: "🛡", label: "ZDR (enforced)" };
    case "tee-unverified":
      return { glyph: "⚠", label: "TEE (unconfirmed)" };
    case "zdr-policy":
      return { glyph: "⚠", label: "ZDR (by policy)" };
    default:
      return { glyph: "•", label: "Standard" };
  }
}

// Build a ranked picker entry for one model.
export function pickerEntry(model: PickerModel, opts: { zdrEnforced?: boolean } = {}): PickerEntry {
  const provider = model.provider;
  const attestable = !!(provider && PROVIDER_BY_ID[provider]?.attestable);
  const tier = capabilityTier(provider, model.baseUrl, opts);
  const { glyph, label } = capabilityBadge(tier, attestable);
  return { model, capabilityTier: tier, rank: tierRank(tier), glyph, label, attestable };
}

// Rank a list of models strongest-privacy first. Ties (same tier) break alphabetically
// by provider then id, so the order is stable and deterministic (no Date/random).
export function rankModels(models: PickerModel[], opts: { zdrEnforced?: boolean } = {}): PickerEntry[] {
  return models
    .map((m) => pickerEntry(m, opts))
    .sort(
      (a, b) =>
        a.rank - b.rank ||
        (a.model.provider ?? "").localeCompare(b.model.provider ?? "") ||
        (a.model.id ?? "").localeCompare(b.model.id ?? ""),
    );
}

// The one-line option string for a picker entry, e.g.
// "◆ Verifiable TEE  ·  tinfoil/deepseek-v4-pro". `current` appends a marker.
export function pickerOptionLabel(e: PickerEntry, current = false): string {
  const who = `${e.model.provider ?? "?"}/${e.model.id ?? "?"}`;
  return `${e.glyph} ${e.label}  ·  ${who}${current ? "  (current)" : ""}`;
}
