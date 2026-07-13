// Local, deterministic structured-PII + secret detection. HONESTY BOUND (the whole
// reason this package exists): this catches STRUCTURED PII — emails, phones, SSNs,
// credit cards, IPs — and prefix-anchored SECRETS (API keys, tokens, private keys)
// via patterns only. It CANNOT catch names, addresses, or contextual PII, and it
// never uses a model (that would send the PII to detect it). So it is "best-effort
// structured detection", never a guarantee. Callers must label it that way — the
// same verified-vs-claimed discipline as the posture engine.

const PLACEHOLDER: Record<PiiType, string> = {
  email: "«email»",
  phone: "«phone»",
  ssn: "«ssn»",
  "credit-card": "«card»",
  ip: "«ip»",
  iban: "«iban»",
  mac: "«mac»",
  "aws-key": "«aws-key»",
  "gh-token": "«token»",
  "api-key": "«api-key»",
  jwt: "«jwt»",
  "private-key": "«private-key»",
};

export type PiiType =
  | "email"
  | "phone"
  | "ssn"
  | "credit-card"
  | "ip"
  | "iban"
  | "mac"
  // Secrets — credentials that are strictly worse to leak than consumer PII. These
  // are prefix-anchored (AKIA…, gh?_…, sk-…, eyJ….….…, PEM blocks), so precision
  // stays high without an entropy heuristic that would false-positive on hashes/IDs.
  | "aws-key"
  | "gh-token"
  | "api-key"
  | "jwt"
  | "private-key";

// The secret subset of PiiType. A hit of one of these means a CREDENTIAL is present
// — messaging escalates and the tool-exfil gate treats it as high-severity.
export const SECRET_TYPES: ReadonlySet<PiiType> = new Set<PiiType>([
  "aws-key",
  "gh-token",
  "api-key",
  "jwt",
  "private-key",
]);

// Order matters: run more-specific/structured patterns first so a card isn't also
// counted as a phone. Credit-card + phone are validated further below. Several types
// (api-key) intentionally have multiple pattern entries — detectPii accumulates them
// under one type.
const PATTERNS: { type: PiiType; re: RegExp; validate?: (m: string) => boolean }[] = [
  { type: "email", re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  { type: "ssn", re: /\b\d{3}-\d{2}-\d{4}\b/g },
  // ── secrets (prefix-anchored, high precision) ──────────────────────────────
  // PEM private-key block — match the whole block so redaction removes the key body.
  { type: "private-key", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g },
  // AWS access key id (AKIA / ASIA + 16 upper-alnum).
  { type: "aws-key", re: /\bA(?:KIA|SIA)[0-9A-Z]{16}\b/g },
  // GitHub tokens: ghp_/gho_/ghu_/ghs_/ghr_ + 36+ base62.
  { type: "gh-token", re: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g },
  // JWT: three base64url segments. `eyJ` is base64 of `{"` — a strong header marker.
  { type: "jwt", re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  // OpenAI/Anthropic/Privateer & generic `sk-` secret keys.
  { type: "api-key", re: /\bsk-[A-Za-z0-9_-]{16,}\b/g },
  // Slack tokens (bot/user/app/refresh/legacy).
  { type: "api-key", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  // Google API key.
  { type: "api-key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  // Stripe live secret / restricted keys.
  { type: "api-key", re: /\b[sr]k_live_[0-9A-Za-z]{20,}\b/g },
  // ── consumer PII ───────────────────────────────────────────────────────────
  // 13–19 digit runs (optionally space/dash grouped) that pass the Luhn check — this
  // sharply cuts false positives vs "any long number".
  { type: "credit-card", re: /\b(?:\d[ -]?){13,19}\b/g, validate: luhn },
  // IPv4 with each octet 0–255.
  { type: "ip", re: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g },
  // IBAN: 2-letter country + 2 check digits + 11–30 alphanumerics, mod-97 validated
  // (cuts false positives on random alphanumeric runs sharply).
  { type: "iban", re: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g, validate: ibanValid },
  // MAC address (colon or dash separated).
  { type: "mac", re: /\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g },
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

// IBAN mod-97 check (ISO 13616): move the first 4 chars to the end, map letters to
// numbers (A=10…Z=35), and verify the big-integer mod 97 === 1.
function ibanValid(s: string): boolean {
  const iban = s.toUpperCase();
  if (iban.length < 15 || iban.length > 34) return false;
  const rearranged = iban.slice(4) + iban.slice(0, 4);
  let remainder = 0;
  for (const ch of rearranged) {
    const code = ch >= "A" && ch <= "Z" ? (ch.charCodeAt(0) - 55).toString() : ch;
    for (const d of code) remainder = (remainder * 10 + (d.charCodeAt(0) - 48)) % 97;
  }
  return remainder === 1;
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

// True when any hit is a credential (not merely consumer PII). Drives the escalated
// wording + safer defaults in the gates — a leaked secret is strictly worse.
export function hasSecrets(hits: PiiHit[]): boolean {
  return hits.some((h) => SECRET_TYPES.has(h.type));
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
    iban: ["IBAN", "IBANs"],
    mac: ["MAC address", "MAC addresses"],
    "aws-key": ["AWS key", "AWS keys"],
    "gh-token": ["GitHub token", "GitHub tokens"],
    "api-key": ["API key", "API keys"],
    jwt: ["JWT", "JWTs"],
    "private-key": ["private key", "private keys"],
  };
  return hits.map((h) => `${h.count} ${label[h.type][h.count === 1 ? 0 : 1]}`).join(", ");
}
