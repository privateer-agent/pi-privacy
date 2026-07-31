// The PII allowlist — values the gate must NOT count as PII.
//
// Why this exists: structured detection is pattern-based, so it fires on anything
// email-SHAPED or IP-SHAPED regardless of whether it is anyone's personal data. A
// repository full of `noreply@users.noreply.github.com` commit trailers, `user@
// example.com` doc snippets and `127.0.0.1` in a config produces a prompt on every
// turn, and a gate that cries wolf on every turn is a gate you learn to dismiss
// without reading. Suppressing the KNOWN-benign shapes is what keeps the real hit
// legible.
//
// HONESTY BOUND: an allowlist can only ever make detection weaker, so it is bounded
// on purpose —
//   * the built-in defaults are limited to values that are reserved-by-standard or
//     structurally non-personal (RFC 2606/6761 example+test domains, loopback and
//     link-local addresses, no-reply senders). Nothing "probably fine" is in here.
//   * a suppressed match is COUNTED and reported (scanPii().suppressed), never
//     silently vanished — "3 emails, 2 allowlisted" is the honest form.
//   * user entries come from YOUR config only. A project-local pi-privacy.config.json
//     may not add any (see clampProjectConfig): "allowlist my address" from a repo you
//     just cloned is an off switch wearing a different hat.
//   * secrets are never default-allowed. You can allowlist a specific token yourself,
//     but nothing here does it for you.

import type { PiiType } from "./detect.ts";

// Decides whether one matched value of one type is allowed (i.e. not PII here).
export type AllowMatcher = (type: PiiType, value: string) => boolean;

// Reserved / structurally non-personal shapes, always applied unless a caller opts
// out. Kept deliberately short — every entry is a hole, so each one has to earn it.
export const DEFAULT_ALLOW: readonly string[] = [
  // RFC 2606 example domains + RFC 6761 special-use TLDs, and their subdomains.
  "@example.com",
  "@example.org",
  "@example.net",
  "@example",
  "@test",
  "@invalid",
  "@localhost",
  "@local",
  // Git/GitHub machine senders — the single biggest source of "N emails detected"
  // in a repository, and by construction not a mailbox anyone reads.
  "@users.noreply.github.com",
  "noreply@*",
  "no-reply@*",
  "donotreply@*",
  "do-not-reply@*",
  // Loopback, unspecified, broadcast, link-local. NOTE private LAN ranges
  // (10/8, 172.16/12, 192.168/16) are deliberately NOT here: they identify a real
  // host on a real network, which is exactly the thing the gate is for.
  "127.0.0.0/8",
  "0.0.0.0",
  "255.255.255.255",
  "169.254.0.0/16",
];

type Rule =
  // `@example.com` / `example.com` — an email whose domain is this or a subdomain.
  | { kind: "domain"; domain: string }
  // `10.0.0.0/8` — an IPv4 inside this block.
  | { kind: "cidr"; net: number; mask: number }
  // anything else, `*` globbing, matched against the whole detected value.
  | { kind: "glob"; re: RegExp };

// `1.2.3.4` shaped (so it is classified as an address, not as a domain name).
const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;

function ipToInt(ip: string): number | undefined {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return undefined;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function globToRe(pattern: string): RegExp {
  const body = pattern
    .split("*")
    .map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
    .join(".*");
  return new RegExp(`^${body}$`, "i");
}

// Parse one entry. Returns undefined for an unusable entry so the caller can warn
// rather than silently install a rule that matches nothing (or everything).
function parseRule(raw: string): Rule | undefined {
  const entry = raw.trim();
  if (!entry) return undefined;
  // A bare `*` would allow every value of every type — that is `piiPolicy: "off"`
  // spelled deceptively, and it is not available here.
  if (/^\*+$/.test(entry)) return undefined;

  const cidr = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(entry);
  if (cidr) {
    const net = ipToInt(cidr[1]);
    const len = Number(cidr[2]);
    if (net === undefined || len > 32) return undefined;
    const mask = len === 0 ? 0 : (0xffffffff << (32 - len)) >>> 0;
    return { kind: "cidr", net: (net & mask) >>> 0, mask };
  }
  if (entry.startsWith("@")) {
    const domain = entry.slice(1).toLowerCase();
    return domain ? { kind: "domain", domain } : undefined;
  }
  // A bare hostname (dots, no `@`, not an address) reads as "mail at this domain".
  if (!entry.includes("@") && entry.includes(".") && !entry.includes("*") && !IPV4.test(entry)) {
    return { kind: "domain", domain: entry.toLowerCase() };
  }
  return { kind: "glob", re: globToRe(entry) };
}

function ruleMatches(rule: Rule, type: PiiType, value: string): boolean {
  switch (rule.kind) {
    case "domain": {
      if (type !== "email") return false;
      const at = value.lastIndexOf("@");
      if (at < 0) return false;
      const domain = value.slice(at + 1).toLowerCase();
      return domain === rule.domain || domain.endsWith(`.${rule.domain}`);
    }
    case "cidr": {
      if (type !== "ip") return false;
      const n = ipToInt(value);
      return n !== undefined && ((n & rule.mask) >>> 0) === rule.net;
    }
    case "glob":
      return rule.re.test(value);
  }
}

export interface CompileAllowOptions {
  // Include DEFAULT_ALLOW (default true). Set false to gate on the reserved shapes too.
  defaults?: boolean;
  // Called with each entry that could not be parsed. Never silent — an entry you
  // believe is suppressing prompts but isn't is worse than no entry at all.
  warn?: (msg: string) => void;
}

// Compile allowlist entries into a matcher. Entry forms:
//   user@host.com        an exact address (`*` globs, e.g. `*@acme.com`)
//   @acme.com            any address at that domain OR a subdomain of it
//   acme.com             the same (a bare hostname reads as a mail domain)
//   10.0.0.0/8           any IPv4 in the block
//   192.168.1.10         an exact value of any type (globs too, e.g. `ghp_dead*`)
export function compileAllow(entries: readonly string[] = [], opts: CompileAllowOptions = {}): AllowMatcher {
  const { defaults = true, warn } = opts;
  const rules: Rule[] = [];
  for (const raw of [...(defaults ? DEFAULT_ALLOW : []), ...entries]) {
    const rule = parseRule(raw);
    if (rule) rules.push(rule);
    else warn?.(`piiAllow entry ${JSON.stringify(raw)} is not a usable pattern — ignoring it.`);
  }
  return (type, value) => rules.some((r) => ruleMatches(r, type, value));
}
