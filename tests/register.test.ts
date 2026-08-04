import { test } from "node:test";
import assert from "node:assert/strict";
import { registerable, providerConfig, nearApiKey } from "../src/ext/register.ts";
import { PRIVACY_PROVIDERS, PROVIDER_BY_ID } from "../src/providers/catalog.ts";

test("Pi's own providers are never re-registered — that would clobber their model lists", () => {
  for (const id of ["openrouter", "fireworks"]) {
    const p = PROVIDER_BY_ID[id];
    if (p) assert.equal(registerable(p), false, id);
  }
  // "custom" is a taxonomy entry, not an endpoint anyone can be registered against.
  const custom = PROVIDER_BY_ID.custom;
  if (custom) assert.equal(registerable(custom), false);
  // A catalog entry with no baseUrl has nothing to register.
  assert.equal(registerable({ ...PRIVACY_PROVIDERS[0], id: "x", baseUrl: undefined } as any), false);
});

test("the config-only privacy providers are the ones registered", () => {
  const ids = PRIVACY_PROVIDERS.filter(registerable).map((p) => p.id);
  for (const id of ["tinfoil", "nearai", "venice", "ollama", "privateer"]) assert.ok(ids.includes(id), id);
});

test("a keyed provider gets the env template + auth header, never a literal secret", () => {
  const p = PROVIDER_BY_ID.tinfoil!;
  const cfg = providerConfig(p) as Record<string, any>;
  assert.equal(cfg.baseUrl, p.baseUrl);
  assert.equal(cfg.apiKey, p.keyEnv);
  assert.match(String(cfg.apiKey), /^\$\{/, "an unresolved ${ENV} template, resolved by Pi");
  assert.equal(cfg.authHeader, true);
  assert.equal(cfg.models.length, 1, "one seed model so the provider is selectable at once");
});

test("a local provider gets a placeholder key — the server ignores it and none is real", () => {
  const cfg = providerConfig(PROVIDER_BY_ID.ollama!) as Record<string, any>;
  assert.equal(cfg.apiKey, "local");
  assert.equal(cfg.authHeader, undefined);
});

test("nearApiKey accepts both spellings seen in the wild, preferring NEARAI_", () => {
  assert.equal(nearApiKey({ NEARAI_API_KEY: "a", NEAR_AI_API_KEY: "b" } as NodeJS.ProcessEnv), "a");
  assert.equal(nearApiKey({ NEAR_AI_API_KEY: "b" } as NodeJS.ProcessEnv), "b");
  assert.equal(nearApiKey({} as NodeJS.ProcessEnv), undefined);
});
