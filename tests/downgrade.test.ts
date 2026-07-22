import { test } from "node:test";
import assert from "node:assert/strict";
import { assessDowngrade, downgradeWarning, exposureLevel } from "../src/posture/downgrade.ts";
import { detectPii } from "../src/pii/detect.ts";

const SECRET = detectPii("token ghp_1234567890abcdefghijklmnopqrstuvwxyz");
const PII = detectPii("mail a@b.com");
const NOTHING = detectPii("just some ordinary source code");

test("exposure: verified-TEE and on-device are equally unexposed", () => {
  // Moving between them reveals nothing new — ranking by tier STRENGTH would call
  // tee-verified → local a downgrade and cry wolf.
  assert.equal(exposureLevel("tee-verified"), exposureLevel("local"));
  assert.equal(assessDowngrade("tee-verified", "local", SECRET).downgrade, false);
  assert.equal(assessDowngrade("local", "tee-verified", SECRET).downgrade, false);
});

test("exposure: an unproven enclave claim protects nothing", () => {
  // tee-unverified must NOT sit beside tee-verified — attestation didn't land, so
  // the provider is assumed to read the payload like any other.
  assert.ok(exposureLevel("tee-unverified") > exposureLevel("tee-verified"));
  assert.equal(exposureLevel("tee-unverified"), exposureLevel("zdr-policy"));
  assert.equal(assessDowngrade("tee-verified", "tee-unverified", SECRET).downgrade, true);
});

test("downgrade detected across the ladder, upgrades are not", () => {
  assert.equal(assessDowngrade("tee-verified", "standard", PII).downgrade, true);
  assert.equal(assessDowngrade("zdr-enforced", "zdr-policy", PII).downgrade, true);
  assert.equal(assessDowngrade("standard", "tee-verified", PII).downgrade, false);
  assert.equal(assessDowngrade("zdr-policy", "zdr-policy", PII).downgrade, false);
});

test("an unknown tier is never claimed as a downgrade in either direction", () => {
  assert.equal(assessDowngrade(undefined, "standard", SECRET).downgrade, false);
  assert.equal(assessDowngrade("tee-verified", undefined, SECRET).downgrade, false);
});

test("severity escalates on credentials and is 'none' when nothing was detected", () => {
  assert.equal(assessDowngrade("tee-verified", "standard", SECRET).severity, "secret");
  assert.equal(assessDowngrade("tee-verified", "standard", PII).severity, "pii");
  assert.equal(assessDowngrade("tee-verified", "standard", NOTHING).severity, "none");
});

test("the warning names both tiers, what's carried, and the honesty bound", () => {
  const a = assessDowngrade("tee-verified", "standard", SECRET);
  const msg = downgradeWarning(a, SECRET, "openrouter/gpt-x");
  assert.match(msg, /Verified TEE/);
  assert.match(msg, /Standard/);
  assert.match(msg, /GitHub token/);
  assert.match(msg, /openrouter\/gpt-x/);
  assert.match(msg, /best-effort/i, "never presents detection as a full inventory");
});
