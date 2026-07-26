import { test } from "node:test";
import assert from "node:assert/strict";
import { toolResultText, redactToolResultContent } from "../src/ext/results.ts";
import { SECRET_TYPES } from "../src/pii/detect.ts";

const KEY = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";

test("toolResultText flattens the shapes a tool result actually takes", () => {
  assert.equal(toolResultText("plain"), "plain");
  assert.equal(toolResultText([{ type: "text", text: "a" }, { type: "text", text: "b" }]), "a\nb");
  assert.equal(toolResultText(["a", "b"]), "a\nb");
  assert.equal(toolResultText(undefined), "");
  // An unfamiliar shape still gets scanned — detection must not miss a secret just
  // because a custom tool returned something we didn't anticipate.
  assert.match(toolResultText({ nested: { token: KEY } }), new RegExp(KEY));
});

test("redaction preserves the result's shape", () => {
  const parts = [{ type: "text", text: `TOKEN=${KEY}` }];
  const out = redactToolResultContent(parts) as { type: string; text: string }[];
  assert.equal(out[0].type, "text", "the part keeps its other fields");
  assert.equal(out[0].text, "TOKEN=«token»");
  assert.equal(redactToolResultContent(`export A=${KEY}`), "export A=«token»");
});

test("credentials only — consumer PII in a tool result is left byte-for-byte alone", () => {
  // Rewriting an email out of a file the agent is about to edit corrupts its view of
  // that file for no privacy gain (the send-side gate already covers the model).
  const src = "contact: a@b.com\n192.168.1.9\n";
  assert.equal(redactToolResultContent(src), undefined, "nothing to redact");
  assert.equal(redactToolResultContent(src + KEY, SECRET_TYPES), "contact: a@b.com\n192.168.1.9\n«token»");
});

test("unchanged content returns undefined, not a copy", () => {
  assert.equal(redactToolResultContent("nothing sensitive here"), undefined);
  assert.equal(redactToolResultContent([{ type: "text", text: "clean" }]), undefined);
});

test("a shape we cannot rebuild returns undefined so the caller can say so", () => {
  // We deliberately do NOT rewrite a JSON serialization of an unknown object — that
  // would hand the tool back a different structure than it returned. The caller
  // reports "could not redact" instead of claiming a redaction that didn't happen.
  assert.equal(redactToolResultContent({ nested: { token: KEY } }), undefined);
});
