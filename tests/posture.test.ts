import { test } from "node:test";
import assert from "node:assert/strict";
import { TIERS, tierRank, tierFromTeePosture } from "../src/posture/tiers.ts";
import { effectiveTier, isLocalEndpoint, PROVIDER_BY_ID } from "../src/index.ts";

test("only tee-verified is cryptographically verified", () => {
  const crypto = Object.values(TIERS).filter((t) => t.verifiability === "cryptographic");
  assert.deepEqual(crypto.map((t) => t.tier), ["tee-verified"]);
});

test("verified and asserted tiers never share a label", () => {
  const labels = Object.values(TIERS).map((t) => t.label);
  assert.equal(new Set(labels).size, labels.length); // all distinct
  // ZDR tiers must not read as "verified".
  assert.doesNotMatch(TIERS["zdr-policy"].label, /verified/i);
  assert.doesNotMatch(TIERS["zdr-enforced"].label, /verified/i);
});

test("tierRank orders strongest privacy first", () => {
  assert.ok(tierRank("tee-verified") < tierRank("zdr-enforced"));
  assert.ok(tierRank("local") < tierRank("zdr-policy"));
  assert.ok(tierRank("zdr-policy") < tierRank("standard"));
});

test("TeePosture maps onto the ladder", () => {
  assert.equal(tierFromTeePosture("green"), "tee-verified");
  assert.equal(tierFromTeePosture("yellow"), "tee-unverified");
  assert.equal(tierFromTeePosture("red"), "standard");
});

test("isLocalEndpoint detects loopback", () => {
  assert.equal(isLocalEndpoint("http://localhost:11434/v1"), true);
  assert.equal(isLocalEndpoint("http://127.0.0.1:1234/v1"), true);
  assert.equal(isLocalEndpoint("https://api.openai.com/v1"), false);
});

test("effectiveTier: openrouter is posture-aware", () => {
  assert.equal(effectiveTier("openrouter"), "zdr-policy");
  assert.equal(effectiveTier("openrouter", { zdrEnforced: true }), "zdr-enforced");
});

test("effectiveTier: custom on a loopback url becomes local", () => {
  assert.equal(effectiveTier("custom"), "standard");
  assert.equal(effectiveTier("custom", { baseUrl: "http://localhost:1234/v1" }), "local");
});

test("effectiveTier: TEE providers advertise their ceiling pre-attestation", () => {
  assert.equal(effectiveTier("tinfoil"), "tee-verified");
  assert.equal(effectiveTier("nearai"), "tee-verified");
  assert.ok(PROVIDER_BY_ID["tinfoil"].attestable);
  assert.ok(PROVIDER_BY_ID["nearai"].attestable);
});

test("unknown provider is standard", () => {
  assert.equal(effectiveTier("groq"), "standard");
});
