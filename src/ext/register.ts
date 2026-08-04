// Registering the config-only privacy providers with Pi.
//
// Pi ships some of these already (openrouter, fireworks); registering those again
// would clobber their real model listings with our single seed model, so they're
// skipped. What's left are the providers Pi has no built-in for — the whole reason
// a user installs this package and finds tinfoil/nearai/venice/ollama/privateer in
// their model list at all.

import type { PrivacyProvider } from "../providers/catalog.ts";

// Config-only providers Pi doesn't ship: register these. Built-ins + custom skipped.
const BUILTIN = new Set(["openrouter", "fireworks"]);

// One seed model per provider so the provider is selectable immediately after
// install. Not a catalog — the host's own model list takes over once configured.
const SEED_MODELS: Record<string, string> = {
  tinfoil: "deepseek-v4-pro",
  nearai: "zai-org/GLM-5.1-FP8",
  venice: "qwen3-coder-480b-a35b-instruct-turbo",
  ollama: "llama3.1",
  privateer: "near/zai-org/GLM-5.1-FP8",
};

export function registerable(p: PrivacyProvider): boolean {
  return !!p.baseUrl && !BUILTIN.has(p.id) && p.id !== "custom";
}

export function providerConfig(p: PrivacyProvider): unknown {
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

export function nearApiKey(env: NodeJS.ProcessEnv = process.env): string | undefined {
  // Both spellings are used in the wild (see privateer redact.ts).
  return env.NEARAI_API_KEY ?? env.NEAR_AI_API_KEY;
}
