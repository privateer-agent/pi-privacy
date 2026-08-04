// Reading and rewriting the outbound provider payload for the PII gate.
//
// Pure: no policy, no prompts. `payloadText` is what detection SEES (the whole
// conversation as it would go on the wire); `redactPayloadPii` is the structural
// rewrite that masks it in place, preserving the payload's shape so the provider
// still receives a well-formed request.

import { redactPii } from "../pii/detect.ts";
import type { AllowMatcher } from "../pii/allow.ts";

// Serialize the outbound messages for detection. Falls back to the whole payload,
// then to "" — a payload we can't stringify is one we can't honestly scan, and an
// empty string is the safe answer (no claim of having found nothing in it).
export function payloadText(payload: any): string {
  try {
    return JSON.stringify(payload?.messages ?? payload ?? "");
  } catch {
    return "";
  }
}

// Mask PII in the payload's message content (string or content-part arrays),
// returning a NEW payload. Anything we don't recognize is passed through untouched
// rather than dropped — a redaction that silently loses a message would corrupt the
// conversation to protect it.
export function redactPayloadPii(payload: any, allow?: AllowMatcher): any {
  if (!payload || typeof payload !== "object" || !Array.isArray(payload.messages)) return payload;
  const mask = (s: string) => redactPii(s, undefined, allow);
  const messages = payload.messages.map((m: any) => {
    if (typeof m?.content === "string") return { ...m, content: mask(m.content) };
    if (Array.isArray(m?.content)) {
      return {
        ...m,
        content: m.content.map((p: any) => (typeof p?.text === "string" ? { ...p, text: mask(p.text) } : p)),
      };
    }
    return m;
  });
  return { ...payload, messages };
}
