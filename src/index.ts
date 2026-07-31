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

// Privacy-ranked model picker (pure): rank the models a user can switch to by the
// strongest privacy each can offer, for the `/models` command.
export {
  type PickerModel,
  type PickerEntry,
  type VerifiedTeeSignal,
  capabilityTier,
  pickerEntry,
  rankModels,
  pickerOptionLabel,
} from "./posture/picker.ts";

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

// Zero-code config loader (env + optional JSON file) — how a marketplace install
// configures the extension without writing TypeScript. Exported so hosts can reuse
// or pre-seed it (e.g. layer their own defaults under the ambient config).
export {
  type ConfigurableOptions,
  type LoadConfigDeps,
  loadConfig,
  optionsFromEnv,
  sanitizeConfig,
  clampProjectConfig,
} from "./config.ts";

// Tool-exfiltration assessor (pure): is a tool call an egress channel, where to, and
// does it name a credential file whose contents are the payload.
export {
  type ToolAssessment,
  assessToolCall,
  firstRemoteUrl,
  splitCommands,
  sensitiveFileRefs,
} from "./ext/toolgate.ts";

// The tool-surface axis (pure): who supplied each tool in the session (provenance)
// and what it DECLARES it can reach — the "who else is in the room?" question no
// per-call gate can answer.
export {
  type ToolProvenance,
  type ToolReach,
  type ToolInfoLike,
  type ToolSurfaceEntry,
  type SurfaceSummary,
  toolProvenance,
  toolReach,
  isRepoSupplied,
  classifyTool,
  rankSurface,
  summarizeSurface,
  surfaceLine,
  surfaceReport,
} from "./surface/tools.ts";

// The observed-egress ledger (pure): where tool calls actually went, as opposed to
// where a tool's schema says it could go. A floor, never a full accounting.
export {
  type EgressObservation,
  type EgressLedger,
  UNNAMED_HOST,
  createLedger,
  hostOf,
  recordEgress,
  ledgerHosts,
  observationLine,
  ledgerReport,
} from "./surface/ledger.ts";

// Tool-RESULT (ingest) helpers (pure): what a result carries, and redaction that
// preserves the result's shape.
export { toolResultText, redactToolResultContent } from "./ext/results.ts";

// Local structured-PII + secret detection (best-effort; emails/phones/SSNs/cards/IPs,
// API keys/tokens/private keys).
export {
  type PiiType,
  type PiiHit,
  type PiiScan,
  type PiiSample,
  type PiiBaseline,
  type ScanOptions,
  SECRET_TYPES,
  detectPii,
  scanPii,
  hasPii,
  hasSecrets,
  secretHits,
  redactPii,
  summarizePii,
  maskPii,
  piiDetail,
  newPii,
  mergePiiBaseline,
} from "./pii/detect.ts";

// The PII allowlist: values the gate does not treat as PII (reserved example/test
// domains, loopback addresses, no-reply senders, plus your own entries).
export { type AllowMatcher, type CompileAllowOptions, compileAllow, DEFAULT_ALLOW } from "./pii/allow.ts";
