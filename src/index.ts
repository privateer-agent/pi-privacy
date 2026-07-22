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

// Attestation engine (ported from privateer 0.2, minus the private server-proxy path).
export {
  type TeePosture,
  type AttestConfig,
  type Attestation,
  type TinfoilAttestation,
  type TinfoilTransport,
  NEARAI_BASE_URL,
  TINFOIL_BASE_URL,
  randomNonce,
  fetchAttestation,
  interpretReport,
  teePosture,
  httpsTransport,
  fetchTinfoilAttestation,
  interpretTinfoilDoc,
  tinfoilTeePosture,
} from "./attest/attestation.ts";

export {
  type CapturedCert,
  installAttestationDispatcher,
  getCapturedCert,
  capturedHosts,
  dispatcherTransport,
} from "./attest/dispatcher.ts";

export { effectiveTier } from "./posture/effective.ts";

// Posture-downgrade assessment: does switching models lower the ceiling over
// context already known to carry sensitive material?
export {
  type DowngradeAssessment,
  exposureLevel,
  assessDowngrade,
  downgradeWarning,
} from "./posture/downgrade.ts";

// Posture verification (attestation-backed) + the Pi extension entry.
export {
  type PostureResult,
  type VerifyOptions,
  verifyModelPosture,
} from "./posture/verify.ts";

export {
  type PiPrivacyOptions,
  type BadgeSink,
  makePiPrivacyExtension,
  default as piPrivacyExtension,
} from "./extension.ts";

export { veniceRequestPatch, openRouterZdrPatch } from "./ext/patches.ts";

// Tool-exfiltration assessor (pure): is a tool call an egress channel, and where to.
export {
  type ToolAssessment,
  assessToolCall,
  firstRemoteUrl,
  splitCommands,
} from "./ext/toolgate.ts";

// Local structured-PII + secret detection (best-effort; emails/phones/SSNs/cards/IPs,
// API keys/tokens/private keys).
export {
  type PiiType,
  type PiiHit,
  SECRET_TYPES,
  detectPii,
  hasPii,
  hasSecrets,
  redactPii,
  summarizePii,
} from "./pii/detect.ts";
