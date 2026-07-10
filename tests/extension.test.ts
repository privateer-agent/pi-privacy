import { test } from "node:test";
import assert from "node:assert/strict";
import { veniceRequestPatch, openRouterZdrPatch } from "../src/ext/patches.ts";
import { verifyModelPosture } from "../src/posture/verify.ts";
import { makePiPrivacyExtension } from "../src/extension.ts";
import type { TinfoilTransport } from "../src/attest/attestation.ts";
import crypto from "node:crypto";

// ── request patches (pure) ───────────────────────────────────────────────────

test("veniceRequestPatch disables the venice system prompt without dropping fields", () => {
  const out = veniceRequestPatch({ model: "x", messages: [] });
  assert.equal(out.model, "x");
  assert.deepEqual(out.venice_parameters, { include_venice_system_prompt: false });
});

test("veniceRequestPatch merges into existing venice_parameters", () => {
  const out = veniceRequestPatch({ venice_parameters: { foo: 1 } });
  assert.deepEqual(out.venice_parameters, { foo: 1, include_venice_system_prompt: false });
});

test("openRouterZdrPatch pins zdr routing (verified OpenRouter params)", () => {
  const out = openRouterZdrPatch({ model: "x", provider: { sort: "price" } });
  assert.deepEqual(out.provider, { sort: "price", zdr: true, data_collection: "deny" });
});

// ── verifyModelPosture ───────────────────────────────────────────────────────

function sevSnpTransport(keyHashHex: string): TinfoilTransport {
  return async () => {
    const report = Buffer.alloc(0x90);
    Buffer.from(keyHashHex, "hex").copy(report, 0x50);
    return {
      doc: {
        format: "https://tinfoil.sh/predicate/sev-snp-guest/v2",
        body: report.toString("base64"),
      },
      liveTlsKeyFp: keyHashHex,
    };
  };
}

test("verifyModelPosture(tinfoil) → tee-verified with a matching key", async () => {
  const key = crypto.createHash("sha256").update("k").digest("hex");
  const res = await verifyModelPosture("tinfoil", "deepseek-v4-pro", {
    transport: sevSnpTransport(key),
  });
  assert.equal(res.tier, "tee-verified");
  assert.equal(res.teePosture, "green");
});

test("verifyModelPosture(tinfoil) failure → tee-unverified, not standard", async () => {
  const res = await verifyModelPosture("tinfoil", "m", {
    transport: async () => {
      throw new Error("network down");
    },
  });
  assert.equal(res.tier, "tee-unverified");
  assert.match(res.error!, /network down/);
});

test("verifyModelPosture(openrouter) reflects enforcement", async () => {
  assert.equal((await verifyModelPosture("openrouter", "m")).tier, "zdr-policy");
  assert.equal((await verifyModelPosture("openrouter", "m", { zdrEnforced: true })).tier, "zdr-enforced");
});

test("verifyModelPosture(ollama) → local", async () => {
  assert.equal((await verifyModelPosture("ollama", "llama3.1")).tier, "local");
});

// ── extension wiring (fake pi) ───────────────────────────────────────────────

function fakePi() {
  const providers: string[] = [];
  const handlers: Record<string, (e: any, c: any) => any> = {};
  const commands: string[] = [];
  return {
    providers,
    handlers,
    commands,
    registerProvider(name: string) {
      providers.push(name);
    },
    registerCommand(name: string) {
      commands.push(name);
    },
    on(event: string, handler: (e: any, c: any) => any) {
      handlers[event] = handler;
    },
  };
}

test("extension registers config-only providers, not built-ins", () => {
  const pi = fakePi();
  makePiPrivacyExtension({ installDispatcher: false })(pi as any);
  assert.deepEqual(pi.providers.sort(), ["nearai", "ollama", "privateer-api", "tinfoil", "venice"]);
  assert.ok(!pi.providers.includes("openrouter")); // built-in, left to Pi
  assert.ok(!pi.providers.includes("fireworks"));
  assert.ok(pi.commands.includes("verify"));
});

test("before_provider_request patches venice only when venice is current", async () => {
  const pi = fakePi();
  makePiPrivacyExtension({ installDispatcher: false, piiPolicy: "off" })(pi as any);
  const req = pi.handlers["before_provider_request"]; // now async
  const sel = pi.handlers["model_select"];

  // No model selected → no patch.
  assert.equal(await req({ payload: { a: 1 } }, {}), undefined);

  // Select venice → venice payload is patched.
  sel({ model: { provider: "venice", id: "m" } }, {});
  const out = await req({ payload: { a: 1 } }, {});
  assert.equal((out as any).venice_parameters.include_venice_system_prompt, false);

  // Switch to a non-venice provider → no patch again.
  sel({ model: { provider: "groq", id: "m" } }, {});
  assert.equal(await req({ payload: { a: 1 } }, {}), undefined);
});

test("PII gate: warns/redacts below TEE, skips verified-private, remembers choice", async () => {
  const pi = fakePi();
  const asks: string[] = [];
  const ctx = {
    hasUI: true,
    ui: { select: async (title: string) => (asks.push(title), "Redact + remember for session") },
  };
  makePiPrivacyExtension({ installDispatcher: false })(pi as any);
  const req = pi.handlers["before_provider_request"];
  const sel = pi.handlers["model_select"];

  sel({ model: { provider: "openrouter", id: "m" } }, {}); // zdr-policy → below verified-private
  const payload = { messages: [{ role: "user", content: "email me at a@b.com" }] };
  const out1 = await req({ payload }, ctx);
  assert.equal(asks.length, 1, "prompted once");
  assert.doesNotMatch(JSON.stringify(out1), /a@b\.com/, "PII redacted");
  // Second call: choice remembered → no re-prompt, still redacted.
  const out2 = await req({ payload }, ctx);
  assert.equal(asks.length, 1, "not re-prompted");
  assert.doesNotMatch(JSON.stringify(out2), /a@b\.com/);
});

test("resolveTier override skips the PII gate on a verified-private tier", async () => {
  const pi = fakePi();
  const asks: string[] = [];
  const ctx = { hasUI: true, ui: { select: async (t: string) => (asks.push(t), "Redact PII") } };
  makePiPrivacyExtension({ installDispatcher: false, resolveTier: () => "tee-verified" })(pi as any);
  pi.handlers["model_select"]({ model: { provider: "privateer", id: "near/x" } }, {});
  await new Promise((r) => setImmediate(r)); // let refreshPosture resolve the tier
  const payload = { messages: [{ role: "user", content: "email a@b.com" }] };
  const out = await pi.handlers["before_provider_request"]({ payload }, ctx);
  assert.equal(asks.length, 0, "verified-private tier → no PII prompt");
  assert.match(JSON.stringify(out ?? payload), /a@b\.com/, "PII left intact on a TEE channel");
});
