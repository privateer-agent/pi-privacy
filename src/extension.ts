// The Pi extension entry — what a marketplace install (or privateer-agent) loads.
//
// Wires the package together: installs the attestation dispatcher at extension-init
// (spike-proven to intercept provider TLS from here), registers the config-only
// privacy providers, patches venice / OpenRouter requests, tracks the current model
// to compute its posture, and adds a `/verify` command. Structural Pi typing keeps
// it decoupled from Pi's exact internal types (verified against the installed
// ExtensionAPI / ProviderConfigInput in 0.80.3).

import { installAttestationDispatcher, dispatcherTransport } from "./attest/dispatcher.ts";
import { PRIVACY_PROVIDERS, type PrivacyProvider } from "./providers/catalog.ts";
import { veniceRequestPatch, openRouterZdrPatch } from "./ext/patches.ts";
import { verifyModelPosture, type PostureResult } from "./posture/verify.ts";
import { TIERS, type PrivacyTier } from "./posture/tiers.ts";
import { detectPii, redactPii, summarizePii } from "./pii/detect.ts";

// Verified-private tiers where PII needs no gate: an attested enclave can't read it,
// and a loopback endpoint never sends it. NOTE zdr-* is NOT here — a ZDR provider
// still SEES the data (it just doesn't retain it), so PII exposure remains.
function isVerifiedPrivate(tier: PrivacyTier | undefined): boolean {
  return tier === "tee-verified" || tier === "local";
}

// Extract the outbound message text for detection, and redact PII structurally in the
// payload's message content (string or content-part arrays).
function payloadText(payload: any): string {
  try {
    return JSON.stringify(payload?.messages ?? payload ?? "");
  } catch {
    return "";
  }
}
function redactPayloadPii(payload: any): any {
  if (!payload || typeof payload !== "object" || !Array.isArray(payload.messages)) return payload;
  const messages = payload.messages.map((m: any) => {
    if (typeof m?.content === "string") return { ...m, content: redactPii(m.content) };
    if (Array.isArray(m?.content)) {
      return {
        ...m,
        content: m.content.map((p: any) => (typeof p?.text === "string" ? { ...p, text: redactPii(p.text) } : p)),
      };
    }
    return m;
  });
  return { ...payload, messages };
}

// ── structural Pi surface (subset we use) ────────────────────────────────────
interface PiModel {
  provider?: string;
  id?: string;
}
interface PiCtx {
  hasUI?: boolean;
  ui?: {
    notify?: (message: string, level?: string) => void;
    select?: (title: string, options: string[], opts?: unknown) => Promise<string | undefined>;
  };
}
interface PiExtensionApiLike {
  registerProvider?(name: string, config: unknown): void;
  registerCommand?(
    name: string,
    options: { description?: string; handler: (args: unknown, ctx: PiCtx) => unknown },
  ): void;
  on(event: string, handler: (event: any, ctx: PiCtx) => any): void;
}

export interface PiPrivacyOptions {
  // Install the process-wide attestation dispatcher (default true). Set false if the
  // host already installed one (e.g. privateer-agent's boot.ts).
  installDispatcher?: boolean;
  // Register the config-only privacy providers (tinfoil/nearai/venice/ollama) with
  // seed models (default true). Built-in providers (openrouter/fireworks) are left
  // to Pi so their model listings aren't clobbered.
  registerProviders?: boolean;
  // Enforce OpenRouter ZDR routing (default false — opt-in, since a model with no
  // zero-retention endpoint will 404 rather than fall back). VERIFIED honest: when
  // on, requests carry provider.{zdr:true,data_collection:"deny"}, which OpenRouter
  // observably enforces (it 404s if unsatisfiable), so the zdr-enforced badge is earned.
  enforceOpenRouterZdr?: boolean;
  // Called whenever the current model's posture is (re)computed — the badge feed.
  onPosture?: (result: PostureResult) => void;
  // Bind Tinfoil attestation to the real provider connection via the dispatcher
  // (default true when the dispatcher is installed). Falls back to httpsTransport.
  useDispatcherTransport?: boolean;
  // Override the tier resolution for providers pi-privacy doesn't know (e.g. a host's
  // private account channel). Return a PrivacyTier to use it (drives the PII gate +
  // badge), or undefined to fall back to pi-privacy's built-in verified posture.
  resolveTier?: (provider: string, modelId: string) => Promise<PrivacyTier | undefined> | PrivacyTier | undefined;
  // Posture-aware structured-PII policy on outbound requests. "warn" (default):
  // interactively warn + offer redact before sending PII down an UNVERIFIED channel;
  // "redact": silently mask; "off": disabled. Only acts below verified-TEE/local
  // (an attested/on-device channel is safe), and only where a UI can prompt. Detection
  // is best-effort structured PII (emails/phones/SSNs/cards/IPs) — NOT a guarantee.
  piiPolicy?: "warn" | "redact" | "off";
}

// Config-only providers Pi doesn't ship: register these. Built-ins + custom skipped.
const BUILTIN = new Set(["openrouter", "fireworks"]);
const SEED_MODELS: Record<string, string> = {
  tinfoil: "deepseek-v4-pro",
  nearai: "zai-org/GLM-5.1-FP8",
  venice: "qwen3-coder-480b-a35b-instruct-turbo",
  ollama: "llama3.1",
};

function registerable(p: PrivacyProvider): boolean {
  return !!p.baseUrl && !BUILTIN.has(p.id) && p.id !== "custom";
}

function providerConfig(p: PrivacyProvider): unknown {
  const seed = SEED_MODELS[p.id];
  const models = seed
    ? [
        {
          id: seed,
          name: seed,
          reasoning: false,
          input: ["text"] as ("text" | "image")[],
          cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
          contextWindow: 128000,
          maxTokens: 4096,
        },
      ]
    : [];
  const cfg: Record<string, unknown> = { name: p.label, baseUrl: p.baseUrl, api: p.api, models };
  if (p.keyEnv) {
    cfg.apiKey = p.keyEnv; // env template ${...}; Pi resolves it
    cfg.authHeader = true;
  } else if (p.local && models.length) {
    // Pi requires apiKey (or oauth) whenever a provider defines models. Local
    // servers (ollama) ignore the auth header, so a placeholder satisfies the
    // validation without sending a meaningful credential.
    cfg.apiKey = "local";
  }
  return cfg;
}

function nearApiKey(): string | undefined {
  // Both spellings are used in the wild (see privateer redact.ts).
  return process.env.NEARAI_API_KEY ?? process.env.NEAR_AI_API_KEY;
}

export function makePiPrivacyExtension(opts: PiPrivacyOptions = {}) {
  const {
    installDispatcher = true,
    registerProviders = true,
    enforceOpenRouterZdr = false,
    onPosture,
    useDispatcherTransport = true,
    piiPolicy = "warn",
    resolveTier,
  } = opts;

  return function piPrivacy(pi: PiExtensionApiLike): void {
    if (installDispatcher) installAttestationDispatcher();

    if (registerProviders && typeof pi.registerProvider === "function") {
      for (const p of PRIVACY_PROVIDERS) {
        if (registerable(p)) pi.registerProvider(p.id, providerConfig(p));
      }
    }

    let currentProviderId: string | undefined;
    let currentModelId: string | undefined;
    // The VERIFIED tier of the current model (attestation result), cached for the PII
    // gate. Undefined until computed → the gate treats "unknown" as not-verified (safe).
    let currentTier: PrivacyTier | undefined;
    // Session PII decision so we don't re-prompt every turn once the user has chosen.
    let piiChoice: "ask" | "send" | "redact" = "ask";

    // Recompute posture for the current model; cache the tier and publish the badge.
    const refreshPosture = async () => {
      if (!currentProviderId || !currentModelId) return;
      // A host-supplied resolver (e.g. a private account channel pi-privacy doesn't
      // know) wins — otherwise use the built-in verified posture.
      if (resolveTier) {
        const t = await resolveTier(currentProviderId, currentModelId);
        if (t !== undefined) {
          currentTier = t;
          onPosture?.({ providerId: currentProviderId, modelId: currentModelId, tier: t });
          return;
        }
      }
      const result = await verifyModelPosture(currentProviderId, currentModelId, {
        apiKey: currentProviderId === "nearai" ? nearApiKey() : undefined,
        zdrEnforced: currentProviderId === "openrouter" && enforceOpenRouterZdr,
        transport: useDispatcherTransport && installDispatcher ? dispatcherTransport : undefined,
      });
      currentTier = result.tier;
      onPosture?.(result);
    };

    pi.on("model_select", (event) => {
      const model = event?.model as PiModel | undefined;
      currentProviderId = model?.provider;
      currentModelId = model?.id;
      void refreshPosture();
    });

    // Per-provider request patches + the posture-aware PII gate.
    pi.on("before_provider_request", async (event, ctx) => {
      let payload = event?.payload;
      // Provider-specific patches first (scoped to the current provider).
      if (currentProviderId === "venice") payload = veniceRequestPatch(payload);
      else if (currentProviderId === "openrouter" && enforceOpenRouterZdr) payload = openRouterZdrPatch(payload);

      // PII gate: only below a VERIFIED-private tier (TEE-verified/local are safe —
      // the provider can't read the data), and only where we can actually prompt.
      if (piiPolicy !== "off" && !isVerifiedPrivate(currentTier)) {
        const hits = detectPii(payloadText(payload));
        if (hits.length > 0) {
          let action: "send" | "redact" =
            piiChoice !== "ask" ? piiChoice : piiPolicy === "redact" ? "redact" : "send";
          if (piiChoice === "ask" && piiPolicy === "warn" && ctx?.hasUI && typeof ctx.ui?.select === "function") {
            const tierLabel = TIERS[currentTier ?? "standard"].label;
            const choice = await ctx.ui.select(
              `⚠ ${summarizePii(hits)} detected — sending to an unverified channel (${tierLabel}). ` +
                `Best-effort structured-PII detection only, not a guarantee.`,
              ["Send as-is", "Redact PII", "Redact + remember for session", "Send + remember for session"],
            );
            if (choice === "Redact PII") action = "redact";
            else if (choice === "Redact + remember for session") ((action = "redact"), (piiChoice = "redact"));
            else if (choice === "Send + remember for session") ((action = "send"), (piiChoice = "send"));
            else action = "send"; // "Send as-is" or cancelled
          }
          if (action === "redact") payload = redactPayloadPii(payload);
        }
      }

      return payload === event?.payload ? undefined : payload;
    });

    if (typeof pi.registerCommand === "function") {
      pi.registerCommand("verify", {
        description: "Verify the current model's privacy posture (TEE attestation)",
        handler: async (_args, ctx) => {
          if (!currentProviderId || !currentModelId) {
            ctx.ui?.notify?.("No model selected.", "warning");
            return;
          }
          const res = await verifyModelPosture(currentProviderId, currentModelId, {
            apiKey: currentProviderId === "nearai" ? nearApiKey() : undefined,
            zdrEnforced: currentProviderId === "openrouter" && enforceOpenRouterZdr,
            transport: useDispatcherTransport && installDispatcher ? dispatcherTransport : undefined,
          });
          const info = TIERS[res.tier];
          const detail = res.teePosture ? ` [${res.teePosture}]` : "";
          const err = res.error ? ` — ${res.error}` : "";
          ctx.ui?.notify?.(`${info.label}${detail}: ${info.blurb}${err}`, "info");
        },
      });
    }
  };
}

// Default export: the marketplace-installable extension with default options.
export default makePiPrivacyExtension();
