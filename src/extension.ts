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
import { TIERS } from "./posture/tiers.ts";

// ── structural Pi surface (subset we use) ────────────────────────────────────
interface PiModel {
  provider?: string;
  id?: string;
}
interface PiCtx {
  ui?: { notify?: (message: string, level?: string) => void };
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

    // Recompute + publish posture for the current model.
    const refreshPosture = async () => {
      if (!currentProviderId || !currentModelId || !onPosture) return;
      const result = await verifyModelPosture(currentProviderId, currentModelId, {
        apiKey: currentProviderId === "nearai" ? nearApiKey() : undefined,
        zdrEnforced: currentProviderId === "openrouter" && enforceOpenRouterZdr,
        transport: useDispatcherTransport && installDispatcher ? dispatcherTransport : undefined,
      });
      onPosture(result);
    };

    pi.on("model_select", (event) => {
      const model = event?.model as PiModel | undefined;
      currentProviderId = model?.provider;
      currentModelId = model?.id;
      void refreshPosture();
    });

    // Per-provider request patches. Scoped to the current provider so we never
    // mutate a payload bound for a different endpoint.
    pi.on("before_provider_request", (event) => {
      if (currentProviderId === "venice") return veniceRequestPatch(event?.payload);
      if (currentProviderId === "openrouter" && enforceOpenRouterZdr) {
        return openRouterZdrPatch(event?.payload);
      }
      return undefined;
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
