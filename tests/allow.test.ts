import { test } from "node:test";
import assert from "node:assert/strict";
import { compileAllow, DEFAULT_ALLOW } from "../src/pii/allow.ts";
import { detectPii, scanPii, redactPii, maskPii, piiDetail, newPii, mergePiiBaseline } from "../src/pii/detect.ts";

// ── the allowlist ────────────────────────────────────────────────────────────

test("built-in defaults suppress reserved/machine addresses, not real ones", () => {
  const allow = compileAllow();
  const text = [
    "docs say user@example.com",
    "commit by 12345+octocat@users.noreply.github.com",
    "noreply@acme.io sent it",
    "fixture bob@service.test",
    "bind 127.0.0.1 and 0.0.0.0",
    "but write to patrick@realmail.com",
    "and the box at 10.0.0.5",
  ].join("\n");
  const scan = scanPii(text, { allow });
  assert.equal(scan.hits.find((h) => h.type === "email")?.count, 1, "only the real address counts");
  assert.equal(scan.hits.find((h) => h.type === "ip")?.count, 1, "loopback/unspecified suppressed, LAN host kept");
  assert.equal(scan.suppressed.find((h) => h.type === "email")?.count, 4);
  assert.equal(scan.suppressed.find((h) => h.type === "ip")?.count, 2);
});

test("private LAN ranges are deliberately NOT default-allowed", () => {
  const allow = compileAllow();
  for (const ip of ["10.0.0.5", "192.168.1.20", "172.16.4.9"]) {
    assert.equal(detectPii(`host ${ip}`, { allow }).length, 1, `${ip} still counts`);
  }
});

test("entry forms: exact, glob, @domain, bare domain, CIDR", () => {
  const allow = compileAllow(["me@acme.com", "*@corp.acme.io", "@partner.dev", "vendor.net", "10.0.0.0/8", "ghp_dead*"], {
    defaults: false,
  });
  const yes = (t: any, v: string) => assert.equal(allow(t, v), true, `${v} should be allowed`);
  const no = (t: any, v: string) => assert.equal(allow(t, v), false, `${v} should NOT be allowed`);

  yes("email", "me@acme.com");
  yes("email", "ME@ACME.COM"); // case-insensitive
  no("email", "you@acme.com");
  yes("email", "anyone@corp.acme.io");
  yes("email", "a@partner.dev");
  yes("email", "a@eu.partner.dev"); // subdomains of a domain rule
  no("email", "a@notpartner.dev"); // not a suffix match on a label boundary
  yes("email", "billing@vendor.net");
  yes("ip", "10.4.5.6");
  no("ip", "11.4.5.6");
  no("email", "10.4.5.6"); // a CIDR rule only ever allows an ip
  yes("gh-token", "ghp_deadbeefcafebabe0123456789abcdefghij");
  no("gh-token", "ghp_livebeefcafebabe0123456789abcdefghij");
});

test("a bare * is refused — that would be piiPolicy:off in disguise", () => {
  const warned: string[] = [];
  const allow = compileAllow(["*", "**", "  "], { defaults: false, warn: (m) => warned.push(m) });
  assert.equal(allow("email", "a@b.com"), false);
  assert.equal(warned.length, 3, "each unusable entry is reported, never silently dropped");
});

test("defaults can be turned off to gate on the reserved shapes too", () => {
  assert.ok(DEFAULT_ALLOW.length > 0);
  const strict = compileAllow([], { defaults: false });
  assert.equal(detectPii("mail user@example.com", { allow: strict }).length, 1);
});

test("redactPii leaves allowlisted values byte-for-byte alone", () => {
  const allow = compileAllow(["@acme.com"]);
  const out = redactPii("ping me@acme.com or bob@other.com at 127.0.0.1 / 8.8.8.8", undefined, allow);
  assert.match(out, /me@acme\.com/);
  assert.match(out, /127\.0\.0\.1/);
  assert.doesNotMatch(out, /bob@other\.com/);
  assert.doesNotMatch(out, /8\.8\.8\.8/);
});

// ── masked detail ────────────────────────────────────────────────────────────

test("maskPii shows enough to recognize, never enough to reconstruct", () => {
  assert.equal(maskPii("email", "patrick@gmail.com"), "p…k@gmail.com");
  assert.equal(maskPii("email", "pk@gmail.com"), "…@gmail.com"); // short local part isn't spelled out
  assert.equal(maskPii("ip", "192.168.1.20"), "192.168.1.•");
  assert.equal(maskPii("mac", "00:1A:2B:3C:4D:5E"), "00:1A:2B:••:••:••");
  assert.match(maskPii("gh-token", "ghp_1234567890abcdefghijklmnopqrstuvwxyz")!, /^ghp_12… \(\d+ chars\)$/);
  // Types where every digit is sensitive get no sample at all.
  assert.equal(maskPii("ssn", "123-45-6789"), undefined);
  assert.equal(maskPii("credit-card", "4242 4242 4242 4242"), undefined);
});

test("piiDetail breaks down the count, including what was allowlisted", () => {
  const scan = scanPii("a@example.com, patrick@realmail.com, ssn 123-45-6789", { allow: compileAllow() });
  const detail = piiDetail(scan);
  assert.match(detail, /p…k@realmail\.com/, "counted value shown masked");
  assert.doesNotMatch(detail, /patrick@realmail\.com/, "never the raw value");
  assert.match(detail, /1 SSN \(masked — not shown\)/);
  assert.match(detail, /allowlisted \(not counted\): 1 email/);
});

test("samples are capped and deduped per type", () => {
  const many = Array.from({ length: 9 }, (_, i) => `user${i}@mail${i}.com`).join(" ");
  const scan = scanPii(`${many} ${many}`, { samples: 3 });
  assert.equal(scan.hits.find((h) => h.type === "email")?.count, 18);
  assert.equal(scan.samples.length, 3);
  assert.match(piiDetail(scan), /\+15 more/);
});

// ── new-PII-only prompting ───────────────────────────────────────────────────

test("newPii reports only what exceeds the decided baseline", () => {
  const base = mergePiiBaseline(new Map(), [{ type: "email", count: 12 }]);
  assert.deepEqual(newPii([{ type: "email", count: 12 }], base), [], "same context → nothing new");
  assert.deepEqual(newPii([{ type: "email", count: 13 }], base), [{ type: "email", count: 1 }]);
  assert.deepEqual(newPii([{ type: "ssn", count: 1 }], base), [{ type: "ssn", count: 1 }], "a new type is new");
});

test("the baseline takes the max, so a shorter payload can't lower the bar", () => {
  let base = mergePiiBaseline(new Map(), [{ type: "email", count: 12 }]);
  base = mergePiiBaseline(base, [{ type: "email", count: 4 }]);
  assert.equal(base.get("email"), 12);
});
