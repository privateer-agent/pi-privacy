// The graded privacy ladder — the honest-labeling contract, as code.
//
// The single rule this file exists to enforce: NEVER conflate a *verified*
// guarantee with an *asserted* one. A TEE tier means we cryptographically checked
// the enclave (remote attestation + a live-TLS-key match against the report). A
// ZDR tier means the provider *promises* zero retention — we can't verify it, and
// the badge must say so. Local means the bytes never left the machine (a loopback
// endpoint we can observe). Rendering these the same would overclaim; the whole
// credibility of the package rests on keeping them distinct.

// Strongest → weakest. Ordered so a picker can sort by privacy strength.
export type PrivacyTier =
  | "tee-verified" // attestation ran, enclave genuine, live TLS key matched the report
  | "tee-unverified" // provider claims a TEE; attestation incomplete/unconfirmed (TeePosture "yellow")
  | "local" // loopback endpoint — inference on-device, nothing leaves the machine
  | "zdr-enforced" // zero-retention actively pinned this session (e.g. OpenRouter ZDR routing on)
  | "zdr-policy" // zero-retention by provider policy only — not verifiable
  | "standard"; // no special guarantee

// How strong the EVIDENCE is behind a tier — the honest core. Only "cryptographic"
// is a real proof; "observable" is a weak local check (loopback / route pinned);
// "policy" is a promise; "none" is nothing.
export type Verifiability = "cryptographic" | "observable" | "policy" | "none";

export interface TierInfo {
  tier: PrivacyTier;
  // One-word status for the badge. Deliberately different words for verified vs
  // asserted tiers so they never read alike.
  label: string;
  verifiability: Verifiability;
  // Traffic-light bucket, mirroring the 0.2 TeePosture green/yellow/red so the
  // status-bar shield + picker badges keep the same semantics.
  posture: "green" | "yellow" | "red" | "neutral";
  // Honest one-liner shown on hover / in the picker. States the LIMIT of the claim.
  blurb: string;
}

export const TIERS: Record<PrivacyTier, TierInfo> = {
  "tee-verified": {
    tier: "tee-verified",
    label: "Verified TEE",
    verifiability: "cryptographic",
    posture: "green",
    blurb:
      "Confidential-enclave inference, cryptographically verified: remote attestation " +
      "proved genuine TEE hardware and the live TLS key matched the attestation report.",
  },
  "tee-unverified": {
    tier: "tee-unverified",
    label: "TEE (unconfirmed)",
    verifiability: "none",
    posture: "yellow",
    blurb:
      "Provider claims a TEE, but attestation was incomplete or the live key could not " +
      "be matched here — treat as unverified until it goes green.",
  },
  local: {
    tier: "local",
    label: "On-device",
    verifiability: "observable",
    posture: "green",
    blurb: "Runs against a loopback endpoint — inference is local; no prompt leaves the machine.",
  },
  "zdr-enforced": {
    tier: "zdr-enforced",
    label: "ZDR (enforced)",
    verifiability: "observable",
    posture: "green",
    blurb:
      "Zero-retention routing is actively pinned this session, so requests only reach " +
      "endpoints that contractually don't retain data. Policy, not hardware — not attested.",
  },
  "zdr-policy": {
    tier: "zdr-policy",
    label: "ZDR (by policy)",
    verifiability: "policy",
    posture: "yellow",
    blurb:
      "The provider states it doesn't retain data, but this is a policy promise we can't " +
      "verify — not hardware, not attested.",
  },
  standard: {
    tier: "standard",
    label: "Standard",
    verifiability: "none",
    posture: "neutral",
    blurb: "No special privacy guarantee.",
  },
};

// Sort key: strongest privacy first. Used by pickers to rank providers/models.
const ORDER: PrivacyTier[] = [
  "tee-verified",
  "local",
  "zdr-enforced",
  "tee-unverified",
  "zdr-policy",
  "standard",
];
export function tierRank(t: PrivacyTier): number {
  const i = ORDER.indexOf(t);
  return i === -1 ? ORDER.length : i;
}

// Map the 0.2 TeePosture (green/yellow/red) onto the graded ladder, so the ported
// attestation engine's output slots into this vocabulary without a rewrite.
export function tierFromTeePosture(p: "green" | "yellow" | "red"): PrivacyTier {
  return p === "green" ? "tee-verified" : p === "yellow" ? "tee-unverified" : "standard";
}
