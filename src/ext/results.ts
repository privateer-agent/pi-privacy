// The INGEST side of the privacy problem — the pure, unit-testable half.
//
// Every other gate in this package judges data on its way OUT: to the model
// (before_provider_request), off the machine (tool_call), or to a weaker provider
// (model_select). None of them watch data coming IN. But a coding agent pulls
// credentials into its own context constantly — `read .env`, `bash: env`, `aws sts
// …`, a fetched dump — and the moment a secret lands in a tool result it is:
//
//   1. in the conversation, re-sent to the provider on EVERY later turn;
//   2. written to the session file on disk (~/.pi/agent/sessions/*.jsonl) in
//      plaintext, where it outlives the session entirely;
//   3. exactly the material the downgrade guard exists to worry about when the
//      model changes.
//
// Redacting at ingest is strictly stronger than warning at send: the secret never
// enters the transcript at all, so there is nothing to re-send, persist, or downgrade
// out of. Same honesty bound as everywhere else — best-effort structured detection,
// never a guarantee.

import { redactPii, SECRET_TYPES, type PiiType } from "../pii/detect.ts";

// Flatten a tool result's content to text for detection. Pi's tool results are
// normally a string or an array of content parts ({type:"text",text}), but a custom
// tool can return anything, so this falls back to a JSON serialization — detection
// should never miss a secret just because the shape was unfamiliar.
export function toolResultText(content: unknown): string {
  if (content === undefined || content === null) return "";
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content
      .map((p) => (typeof p === "string" ? p : typeof (p as { text?: unknown })?.text === "string" ? (p as { text: string }).text : ""))
      .join("\n");
  }
  try {
    return JSON.stringify(content);
  } catch {
    return String(content);
  }
}

// Redact within a tool result's content, preserving its shape.
//
// Returns the rewritten content, or `undefined` when nothing was rewritten — either
// because there was nothing to redact, or because the shape isn't one we can safely
// rebuild. That distinction matters: the caller must be able to tell "redacted" from
// "couldn't", and say so, instead of reporting a redaction that never happened. We
// deliberately do NOT fall back to rewriting a JSON serialization of an unknown
// shape — that would hand the tool back a different structure than it returned.
export function redactToolResultContent(
  content: unknown,
  only: ReadonlySet<PiiType> = SECRET_TYPES,
): unknown | undefined {
  if (typeof content === "string") {
    const out = redactPii(content, only);
    return out === content ? undefined : out;
  }
  if (Array.isArray(content)) {
    let changed = false;
    const out = content.map((p) => {
      if (typeof p === "string") {
        const r = redactPii(p, only);
        if (r !== p) changed = true;
        return r;
      }
      const text = (p as { text?: unknown })?.text;
      if (typeof text === "string") {
        const r = redactPii(text, only);
        if (r !== text) changed = true;
        return { ...(p as object), text: r };
      }
      return p;
    });
    return changed ? out : undefined;
  }
  return undefined; // unknown shape — the caller reports that it could not redact
}
