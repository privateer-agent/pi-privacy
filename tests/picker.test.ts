import { test } from "node:test";
import assert from "node:assert/strict";
import {
  capabilityTier,
  pickerEntry,
  rankModels,
  pickerOptionLabel,
  type PickerModel,
} from "../src/posture/picker.ts";

test("capabilityTier: attestable TEE providers ceiling at tee-verified", () => {
  assert.equal(capabilityTier("tinfoil", "https://inference.tinfoil.sh/v1"), "tee-verified");
  assert.equal(capabilityTier("nearai", "https://cloud-api.near.ai/v1"), "tee-verified");
});

test("capabilityTier: loopback is on-device even for an unknown provider", () => {
  assert.equal(capabilityTier("lmstudio", "http://localhost:1234/v1"), "local");
  assert.equal(capabilityTier("ollama", "http://127.0.0.1:11434/v1"), "local");
  // A LAN host is NOT local — the overclaim the package exists to prevent.
  assert.equal(capabilityTier("custom", "http://box.local:1234/v1"), "standard");
});

test("capabilityTier: OpenRouter reflects ZDR enforcement", () => {
  assert.equal(capabilityTier("openrouter", "https://openrouter.ai/api/v1"), "zdr-policy");
  assert.equal(
    capabilityTier("openrouter", "https://openrouter.ai/api/v1", { zdrEnforced: true }),
    "zdr-enforced",
  );
});

test("capabilityTier: unknown remote provider is standard", () => {
  assert.equal(capabilityTier("openai", "https://api.openai.com/v1"), "standard");
});

test("pickerEntry: attestable TEE shows 'Verifiable' (never live 'Verified')", () => {
  const e = pickerEntry({ provider: "tinfoil", id: "x", baseUrl: "https://inference.tinfoil.sh/v1" });
  assert.equal(e.attestable, true);
  assert.equal(e.capabilityTier, "tee-verified");
  assert.equal(e.label, "Verifiable TEE"); // capability, not a live proof
  assert.equal(e.glyph, "◆"); // hollow marker, distinct from the solid live shield
  assert.doesNotMatch(e.label, /^Verified/);
});

test("pickerEntry: on-device shows the solid shield (observable now)", () => {
  const e = pickerEntry({ provider: "ollama", id: "llama", baseUrl: "http://localhost:11434/v1" });
  assert.equal(e.glyph, "🛡");
  assert.equal(e.label, "On-device");
});

test("rankModels sorts strongest-privacy first, then alphabetically", () => {
  const models: PickerModel[] = [
    { provider: "openai", id: "gpt", baseUrl: "https://api.openai.com/v1" }, // standard
    { provider: "venice", id: "qwen", baseUrl: "https://api.venice.ai/api/v1" }, // zdr-policy
    { provider: "tinfoil", id: "ds", baseUrl: "https://inference.tinfoil.sh/v1" }, // tee-verified
    { provider: "ollama", id: "llama", baseUrl: "http://localhost:11434/v1" }, // local
  ];
  const order = rankModels(models).map((e) => e.model.provider);
  assert.deepEqual(order, ["tinfoil", "ollama", "venice", "openai"]);
});

test("rankModels breaks ties deterministically by provider then id", () => {
  const models: PickerModel[] = [
    { provider: "fireworks", id: "b", baseUrl: "https://api.fireworks.ai/inference/v1" },
    { provider: "fireworks", id: "a", baseUrl: "https://api.fireworks.ai/inference/v1" },
    { provider: "venice", id: "z", baseUrl: "https://api.venice.ai/api/v1" },
  ];
  // all zdr-policy → sort by provider, then id
  assert.deepEqual(
    rankModels(models).map((e) => `${e.model.provider}/${e.model.id}`),
    ["fireworks/a", "fireworks/b", "venice/z"],
  );
});

test("pickerOptionLabel formats and marks the current model", () => {
  const e = pickerEntry({ provider: "tinfoil", id: "ds", baseUrl: "https://inference.tinfoil.sh/v1" });
  assert.equal(pickerOptionLabel(e), "◆ Verifiable TEE  ·  tinfoil/ds");
  assert.match(pickerOptionLabel(e, true), /\(current\)$/);
});
