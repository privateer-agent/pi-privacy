import { test } from "node:test";
import assert from "node:assert/strict";
import { payloadText, redactPayloadPii } from "../src/ext/payload.ts";
import { compileAllow } from "../src/pii/allow.ts";
import { hasPii } from "../src/pii/detect.ts";

test("payloadText serializes the messages the provider would actually receive", () => {
  const text = payloadText({ model: "m", messages: [{ role: "user", content: "mail me at a@b.io" }] });
  assert.ok(text.includes("a@b.io"));
  assert.ok(!text.includes('"model"'), "only the messages are scanned, not the envelope");
});

test("payloadText never throws — an unscannable payload yields empty, not a crash", () => {
  const cyclic: any = { messages: [] };
  cyclic.messages.push(cyclic);
  assert.equal(payloadText(cyclic), "");
  assert.equal(payloadText(undefined), '""');
});

test("redactPayloadPii masks string content and leaves the envelope intact", () => {
  const payload = { model: "m", temperature: 0, messages: [{ role: "user", content: "ssn 123-45-6789" }] };
  const out = redactPayloadPii(payload);
  assert.equal(out.model, "m");
  assert.equal(out.temperature, 0);
  assert.equal(out.messages[0].role, "user");
  assert.ok(!hasPii(out.messages[0].content));
  assert.equal(payload.messages[0].content, "ssn 123-45-6789", "input is not mutated");
});

test("redactPayloadPii masks text parts and passes non-text parts through untouched", () => {
  const image = { type: "image_url", image_url: { url: "https://x.test/a.png" } };
  const out = redactPayloadPii({
    messages: [{ role: "user", content: [{ type: "text", text: "call 555-867-5309" }, image] }],
  });
  assert.ok(!hasPii(out.messages[0].content[0].text));
  assert.deepEqual(out.messages[0].content[1], image);
});

test("an allowlisted value survives redaction — it was never PII here", () => {
  const allow = compileAllow(["@acme.test"], { defaults: false, warn: () => {} });
  const out = redactPayloadPii(
    { messages: [{ role: "user", content: "me@acme.test and them@other.io" }] },
    allow,
  );
  assert.ok(out.messages[0].content.includes("me@acme.test"));
  assert.ok(!out.messages[0].content.includes("them@other.io"));
});

test("a payload with no messages array is returned as-is, never deformed", () => {
  for (const p of [undefined, null, "text", { prompt: "hi" }]) assert.equal(redactPayloadPii(p), p);
});
