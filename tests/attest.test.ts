import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { gzipSync } from "node:zlib";
import {
  interpretTinfoilDoc,
  tinfoilTeePosture,
  interpretReport,
  teePosture,
} from "../src/attest/attestation.ts";
import { tierFromTeePosture } from "../src/posture/tiers.ts";

// Build a synthetic SEV-SNP attestation doc whose report_data[0:32] (at offset
// 0x50) is `keyHash` — exactly how Tinfoil packs the enclave TLS key fingerprint.
function makeSevSnpDoc(keyHashHex: string, gzip = false) {
  const report = Buffer.alloc(0x90); // >= 0x90 so the 0x50..0x70 slice exists
  Buffer.from(keyHashHex, "hex").copy(report, 0x50);
  let body = report;
  if (gzip) body = gzipSync(report);
  return {
    format: "https://tinfoil.sh/predicate/sev-snp-guest/v2",
    body: body.toString("base64"),
  };
}

const keyHash = crypto.createHash("sha256").update("enclave-tls-key").digest("hex");

test("tinfoil: matched live key → green (verified TEE)", () => {
  const att = interpretTinfoilDoc("inference.tinfoil.sh", makeSevSnpDoc(keyHash), keyHash);
  assert.deepEqual(att.hardware, ["AMD SEV-SNP"]);
  assert.equal(att.attestedTlsKeyFp, keyHash);
  assert.equal(att.tlsKeyMatched, true);
  assert.equal(tinfoilTeePosture(att), "green");
  assert.equal(tierFromTeePosture(tinfoilTeePosture(att)), "tee-verified");
});

test("tinfoil: gzipped body decodes the same", () => {
  const att = interpretTinfoilDoc("h", makeSevSnpDoc(keyHash, true), keyHash);
  assert.equal(att.tlsKeyMatched, true);
  assert.equal(tinfoilTeePosture(att), "green");
});

test("tinfoil: mismatched live key → yellow (attested, unconfirmed)", () => {
  const otherKey = crypto.createHash("sha256").update("different").digest("hex");
  const att = interpretTinfoilDoc("h", makeSevSnpDoc(keyHash), otherKey);
  assert.equal(att.tlsKeyMatched, false);
  assert.equal(tinfoilTeePosture(att), "yellow");
  assert.equal(tierFromTeePosture(tinfoilTeePosture(att)), "tee-unverified");
});

test("tinfoil: no live key → yellow (can't confirm the binding)", () => {
  const att = interpretTinfoilDoc("h", makeSevSnpDoc(keyHash), undefined);
  assert.equal(att.tlsKeyMatched, false);
  assert.equal(tinfoilTeePosture(att), "yellow");
});

test("tinfoil: empty document → red", () => {
  const att = interpretTinfoilDoc("h", {}, keyHash);
  assert.deepEqual(att.hardware, []);
  assert.equal(att.attestedTlsKeyFp, undefined);
  assert.equal(tinfoilTeePosture(att), "red");
  assert.equal(tierFromTeePosture(tinfoilTeePosture(att)), "standard");
});

test("near: signing key + hardware + nonce echo → green", () => {
  const nonce = "abc123";
  const raw = { signing_address: "0xdeadbeef", gpu: "NVIDIA H100", quote: `...${nonce}...` };
  const att = interpretReport("model-x", nonce, raw);
  assert.equal(att.signingAddress, "0xdeadbeef");
  assert.deepEqual(att.hardware, ["NVIDIA"]);
  assert.equal(att.nonceEchoed, true);
  assert.equal(teePosture(att), "green");
});

test("near: no material → red", () => {
  const att = interpretReport("m", "n", { ok: true });
  assert.equal(teePosture(att), "red");
});

test("near: hardware but no signing key → yellow", () => {
  const att = interpretReport("m", "n", { tdx: "Intel TDX quote" });
  assert.deepEqual(att.hardware, ["Intel TDX"]);
  assert.equal(teePosture(att), "yellow");
});
