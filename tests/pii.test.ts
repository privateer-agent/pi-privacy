import { test } from "node:test";
import assert from "node:assert/strict";
import { detectPii, hasPii, hasSecrets, redactPii, summarizePii } from "../src/pii/detect.ts";

test("detects emails, SSNs, IPs", () => {
  const hits = detectPii("Contact a@b.com or c@d.org, SSN 123-45-6789, host 10.0.0.5");
  const types = hits.map((h) => h.type).sort();
  assert.deepEqual(types, ["email", "ip", "ssn"]);
  assert.equal(hits.find((h) => h.type === "email")?.count, 2);
});

test("credit card requires a valid Luhn number", () => {
  assert.ok(hasPii("card 4242 4242 4242 4242")); // valid Luhn (Visa test)
  assert.equal(detectPii("id 1234 5678 9012 3456").some((h) => h.type === "credit-card"), false); // fails Luhn
});

test("detects a formatted phone number but not a bare digit run", () => {
  assert.ok(detectPii("call (415) 555-2671").some((h) => h.type === "phone"));
  assert.equal(detectPii("order 4155552671000").some((h) => h.type === "phone"), false);
});

test("IBAN requires a valid mod-97 checksum; MAC by format", () => {
  assert.ok(detectPii("account GB82WEST12345698765432 please").some((h) => h.type === "iban"));
  assert.equal(detectPii("code GB00WEST12345698765432").some((h) => h.type === "iban"), false); // bad checksum
  assert.ok(detectPii("device 00:1A:2B:3C:4D:5E").some((h) => h.type === "mac"));
});

test("clean text has no PII", () => {
  assert.equal(hasPii("refactor the auth module and add tests"), false);
  assert.deepEqual(detectPii(""), []);
});

test("redactPii masks with typed placeholders, keeps the rest", () => {
  const out = redactPii("email a@b.com and ssn 123-45-6789 please");
  assert.match(out, /«email»/);
  assert.match(out, /«ssn»/);
  assert.match(out, /^email .* and ssn .* please$/);
  assert.doesNotMatch(out, /a@b\.com|123-45-6789/);
});

test("summarizePii pluralizes", () => {
  assert.equal(summarizePii([{ type: "email", count: 2 }, { type: "ssn", count: 1 }]), "2 emails, 1 SSN");
});

// ── secrets ──────────────────────────────────────────────────────────────────

test("detects AWS keys, GitHub tokens, sk-/Slack/Google keys, JWTs", () => {
  const text = [
    "aws AKIAIOSFODNN7EXAMPLE",
    "gh ghp_1234567890abcdefghijklmnopqrstuvwxyz",
    "openai sk-proj-abcdefghijklmnopqrstuvwxyz012345",
    "slack xoxb-123456789012-abcdefABCDEF",
    "google AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456",
    "jwt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF123456",
  ].join("\n");
  const types = detectPii(text).map((h) => h.type).sort();
  assert.deepEqual(types, ["api-key", "aws-key", "gh-token", "jwt"]);
  // sk-, Slack, Google all fold into api-key → count 3.
  assert.equal(detectPii(text).find((h) => h.type === "api-key")?.count, 3);
});

test("detects and redacts a PEM private-key block", () => {
  const pem =
    "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\nQQQ\n-----END OPENSSH PRIVATE KEY-----";
  assert.ok(detectPii(`key:\n${pem}\ndone`).some((h) => h.type === "private-key"));
  const out = redactPii(`key:\n${pem}\ndone`);
  assert.match(out, /«private-key»/);
  assert.doesNotMatch(out, /BEGIN OPENSSH/);
});

test("hasSecrets distinguishes credentials from consumer PII", () => {
  assert.equal(hasSecrets(detectPii("email a@b.com")), false);
  assert.equal(hasSecrets(detectPii("token ghp_1234567890abcdefghijklmnopqrstuvwxyz")), true);
});

test("clean prose has no false-positive secrets", () => {
  assert.equal(hasPii("refactor sk- handling and the aws sdk client wrapper"), false);
});

test("summarizePii labels secrets", () => {
  assert.equal(summarizePii([{ type: "aws-key", count: 1 }, { type: "api-key", count: 2 }]), "1 AWS key, 2 API keys");
});
