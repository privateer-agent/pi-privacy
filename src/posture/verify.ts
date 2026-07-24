import { PROVIDER_BY_ID } from "../providers/catalog.ts";
import { effectiveTier } from "./effective.ts";
import { type PrivacyTier, tierFromTeePosture } from "./tiers.ts";
import {
  fetchTinfoilAttestation,
  fetchAttestation,
  tinfoilTeePosture,
  teePosture,
  httpsTransport,
  type TeePosture,
  type TinfoilTransport,
} from "../attest/attestation.ts";

// The badge/queryable posture for a specific model. For TEE providers this ACTIVELY
// verifies (attestation → green/yellow/red); for everything else it resolves the
// static tier + on-device / ZDR-enforcement. The one place a `tee-verified` verdict
// can legitimately come from — never from effectiveTier() alone.

export interface PostureResult {
  providerId: string;
  modelId: string;
  tier: PrivacyTier;
  teePosture?: TeePosture; // present for TEE providers
  attestation?: unknown; // raw report, for /verify display + external verification
  error?: string; // attestation fetch failed → tier falls back to tee-unverified
}

export interface VerifyOptions {
  apiKey?: string; // for NEAR (report is key-gated)
  baseUrl?: string; // override the provider's default endpoint
  zdrEnforced?: boolean; // OpenRouter: is ZDR routing actively pinned?
  transport?: TinfoilTransport; // inject for tests / to bind to the real connection
}

export async function verifyModelPosture(
  providerId: string,
  modelId: string,
  opts: VerifyOptions = {},
): Promise<PostureResult> {
  const p = PROVIDER_BY_ID[providerId];

  if (p?.id === "tinfoil") {
    try {
      const att = await fetchTinfoilAttestation(
        { baseURL: opts.baseUrl },
        opts.transport ?? httpsTransport,
      );
      const tp = tinfoilTeePosture(att);
      return { providerId, modelId, tier: tierFromTeePosture(tp), teePosture: tp, attestation: att };
    } catch (e) {
      // A TEE provider we couldn't verify is unverified — NOT downgraded to a
      // false "standard": the honest state is "claims TEE, unconfirmed".
      return { providerId, modelId, tier: "tee-unverified", error: (e as Error).message };
    }
  }

  if (p?.id === "nearai") {
    try {
      const att = await fetchAttestation({ apiKey: opts.apiKey, baseURL: opts.baseUrl }, modelId);
      const tp = teePosture(att);
      return { providerId, modelId, tier: tierFromTeePosture(tp), teePosture: tp, attestation: att };
    } catch (e) {
      return { providerId, modelId, tier: "tee-unverified", error: (e as Error).message };
    }
  }

  // Privateer's VERIFIED-TEE verdict comes from the host's account channel (OAuth
  // session + private account server + sealed relay — privateer-agent's job), injected
  // via the extension's resolveTier hook. From pi-privacy alone we only see the public
  // sk-priv- developer key, which is server-proxied and unverifiable end-to-end, so it
  // falls through to its honest zdr-policy floor below (never a TEE claim we can't back).

  // Non-TEE: static tier + on-device detection + ZDR enforcement state.
  return {
    providerId,
    modelId,
    tier: effectiveTier(providerId, { baseUrl: opts.baseUrl, zdrEnforced: opts.zdrEnforced }),
  };
}
