// Local, deterministic structured-PII detection. HONESTY BOUND (the whole reason
// this package exists): this catches STRUCTURED PII — emails, phones, SSNs, credit
// cards, IPs — via patterns only. It CANNOT catch names, addresses, or contextual
// PII, and it never uses a model (that would send the PII to detect it). So it is
// "best-effort structured-PII detection", never a guarantee. Callers must label it
// that way — the same verified-vs-claimed discipline as the posture engine.

const PLACEHOLDER: Record<PiiType, string> = {
  email: "«email»",
  phone: "«phone»",
  ssn: "«ssn»",
  "credit-card": "«card»",
  ip: "«ip»",
};

export type PiiType = "email" | "phone" | "ssn" | "credit-card" | "ip";

// Order matters: run more-specific/structured patterns first so a card isn't also
// counted as a phone. Credit-card + phone are validated further below.
const PATTERNS: { type: PiiType; re: RegExp; validate?: (m: string) => boolean }[] = [
  { type: "email", re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  { type: "ssn", re: /\b\d{3}-\d{2}-\d{4}\b/g },
  // 13–19 digit runs (optionally space/dash grouped) that pass the Luhn check — this
  // sharply cuts false positives vs "any long number".
  { type: "credit-card", re: /\b(?:\d[ -]?){13,19}\b/g, validate: luhn },
  // IPv4 with each octet 0–255.
  { type: "ip", re: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g },
  // North-American / international-ish phone. Deliberately last + conservative to
  // avoid eating IDs; requires a plausible separator or leading +.
  { type: "phone", re: /(?:\+\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b/g },
];

function luhn(s: string): boolean {
  const digits = s.replace(/\D/g, "");
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (alt) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    alt = !alt;
  }
  return sum % 10 === 0;
}

export interface PiiHit {
  type: PiiType;
  count: number;
}

// Detect structured PII in text. Returns the types present with counts (not the raw
// values — we don't want to log the PII we found).
export function detectPii(text: string): PiiHit[] {
  if (!text) return [];
  const counts = new Map<PiiType, number>();
  for (const { type, re, validate } of PATTERNS) {
    for (const m of text.matchAll(re)) {
      if (validate && !validate(m[0])) continue;
      counts.set(type, (counts.get(type) ?? 0) + 1);
    }
  }
  return [...counts.entries()].map(([type, count]) => ({ type, count }));
}

export function hasPii(text: string): boolean {
  return detectPii(text).length > 0;
}

// Redact structured PII in text, replacing each match with a typed placeholder.
export function redactPii(text: string): string {
  let out = text;
  for (const { type, re, validate } of PATTERNS) {
    out = out.replace(re, (m) => (validate && !validate(m) ? m : PLACEHOLDER[type]));
  }
  return out;
}

// Human-readable summary of a hit list, e.g. "2 emails, 1 SSN".
export function summarizePii(hits: PiiHit[]): string {
  const label: Record<PiiType, [string, string]> = {
    email: ["email", "emails"],
    phone: ["phone number", "phone numbers"],
    ssn: ["SSN", "SSNs"],
    "credit-card": ["card number", "card numbers"],
    ip: ["IP address", "IP addresses"],
  };
  return hits.map((h) => `${h.count} ${label[h.type][h.count === 1 ? 0 : 1]}`).join(", ");
}
