import { test } from "node:test";
import assert from "node:assert/strict";
import { detectPii, hasPii, redactPii, summarizePii } from "../src/pii/detect.ts";

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
