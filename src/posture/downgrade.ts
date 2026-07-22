// The posture-DOWNGRADE guard — the leak that no per-request gate can see.
//
// Every other control in this package judges one request, or one tool call, in
// isolation. But a session accumulates: you work for an hour against a verified
// enclave, and the context fills with .env contents, keys, customer rows, source.
// Then you switch models. On the very next turn that ENTIRE history — everything
// the private channel was protecting — is re-sent to the new provider. Nothing
// about the outgoing request looks unusual; it's the same context it always was.
// What changed is the ceiling above it, and only the transition reveals that.
//
// So this module answers one question: does moving from tier A to tier B lower the
// ceiling over context we've already seen carry sensitive material? Pure and
// unit-tested; the extension pairs it with a prompt (and a revert via pi.setModel).

import { type PrivacyTier, TIERS } from "./tiers.ts";
import { type PiiHit, hasSecrets, summarizePii } from "../pii/detect.ts";

// How much the CONTEXT is exposed under a tier — deliberately NOT tierRank(), which
// ranks by strength-of-guarantee for a picker. Here the only question is "can the
// other side read what we send", so tee-verified and local are equal at 0: an
// enclave can't read the payload and a loopback endpoint never receives it, and
// moving between them exposes nothing new (ranking would have called that a
// downgrade and cried wolf). tee-unverified sits with zdr-policy, not with
// tee-verified: an unproven enclave claim protects nothing.
const EXPOSURE: Record<PrivacyTier, number> = {
  "tee-verified": 0, // provider cannot read the payload
  local: 0, // payload never leaves the machine
  "zdr-enforced": 1, // provider reads it; retention observably refused
  "zdr-policy": 2, // provider reads it; retention refused by promise only
  "tee-unverified": 2, // enclave claimed, unproven — assume it reads it
  standard: 3, // read and retained at the provider's discretion
};

export function exposureLevel(tier: PrivacyTier): number {
  return EXPOSURE[tier] ?? 3;
}

export interface DowngradeAssessment {
  // Is the new tier strictly weaker than the old one?
  downgrade: boolean;
  from: PrivacyTier;
  to: PrivacyTier;
  // What the accumulated context is known to hold. "secret" (a credential) is the
  // escalated case; "none" means nothing structured was detected — which is NOT the
  // same as "nothing sensitive is there", since detection is best-effort.
  severity: "secret" | "pii" | "none";
}

// Assess a tier transition against what the session context is known to carry.
// `hits` is the detection from the last outbound payload — i.e. the history that
// would be re-sent to the new provider on the next turn.
export function assessDowngrade(
  from: PrivacyTier | undefined,
  to: PrivacyTier | undefined,
  hits: PiiHit[] = [],
): DowngradeAssessment {
  // An unknown tier can't be compared honestly in either direction: claiming a
  // downgrade we can't substantiate is as wrong as missing one.
  const a = from ?? "standard";
  const b = to ?? "standard";
  return {
    downgrade: from !== undefined && to !== undefined && exposureLevel(b) > exposureLevel(a),
    from: a,
    to: b,
    severity: hits.length === 0 ? "none" : hasSecrets(hits) ? "secret" : "pii",
  };
}

// The warning shown on a downgrade. States the transition, what's in the context
// that would follow the session down, and — per the honesty bound — that structured
// detection is a floor on what's there, never a ceiling.
export function downgradeWarning(a: DowngradeAssessment, hits: PiiHit[], modelLabel?: string): string {
  const target = modelLabel ? ` to ${modelLabel}` : "";
  const carried = hits.length ? `carrying ${summarizePii(hits)}` : "already in context";
  return (
    `⚠ Privacy downgrade: ${TIERS[a.from].label} → ${TIERS[a.to].label}. ` +
    `This session's history — ${carried} — will be re-sent${target} on the next turn. ` +
    `Detection is best-effort structured PII/secrets, so treat it as a floor, not a full inventory.`
  );
}
