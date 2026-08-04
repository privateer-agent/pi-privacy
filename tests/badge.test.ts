import { test } from "node:test";
import assert from "node:assert/strict";
import { postureBadge, renderBadgeTo, DEFAULT_BADGE_SINKS, type BadgeSink } from "../src/ext/badge.ts";
import { TIERS, type PrivacyTier } from "../src/posture/tiers.ts";
import type { PiUi } from "../src/ext/pi-api.ts";

test("the badge glyph tracks the traffic-light posture, so verified never reads as asserted", () => {
  const glyphFor = (tier: PrivacyTier) => postureBadge(tier).split(" ")[0];
  for (const tier of Object.keys(TIERS) as PrivacyTier[]) {
    const expected = { green: "🛡", yellow: "⚠", red: "⛔" }[TIERS[tier].posture as string] ?? "•";
    assert.equal(glyphFor(tier), expected, `${tier} (${TIERS[tier].posture})`);
    assert.ok(postureBadge(tier).includes(TIERS[tier].label));
  }
  // Distinctness is the whole thesis: a verified tier must not render like an
  // asserted one at a glance.
  assert.notEqual(glyphFor("tee-verified"), glyphFor("tee-unverified"));
});

test("an uncomputed tier shows a pending marker, never a ceiling it hasn't earned", () => {
  const badge = postureBadge(undefined);
  assert.match(badge, /checking/);
  for (const tier of Object.keys(TIERS) as PrivacyTier[]) assert.notEqual(badge, postureBadge(tier));
});

test("renderBadgeTo reports false for a surface this UI doesn't expose", () => {
  const empty: PiUi = {};
  for (const sink of DEFAULT_BADGE_SINKS) assert.equal(renderBadgeTo(empty, sink, "k", "b", "local"), false);
  assert.equal(renderBadgeTo(empty, "notify", "k", "b", "local"), false);
  assert.equal(renderBadgeTo({ setStatus() {} }, "bogus" as BadgeSink, "k", "b", "local"), false);
});

test("each sink writes to its own surface, keyed where the host expects a key", () => {
  const calls: string[] = [];
  const ui: PiUi = {
    setStatus: (k, t) => calls.push(`status:${k}=${t}`),
    setWidget: (k, c) => calls.push(`widget:${k}=${c?.join("|")}`),
    setTitle: (t) => calls.push(`title:${t}`),
    notify: (m, l) => calls.push(`notify:${l}:${m}`),
  };
  for (const sink of ["status", "widget", "title", "notify"] as BadgeSink[])
    assert.equal(renderBadgeTo(ui, sink, "pi-privacy", "🛡 ok", "tee-verified"), true);
  assert.deepEqual(calls, [
    "status:pi-privacy=🛡 ok",
    "widget:pi-privacy=🛡 ok",
    "title:🛡 ok",
    "notify:info:🛡 ok",
  ]);
});

test("the notify sink escalates level below green — a weak posture isn't an FYI", () => {
  const levels: (string | undefined)[] = [];
  const ui: PiUi = { notify: (_m, l) => levels.push(l) };
  renderBadgeTo(ui, "notify", "k", "b", "tee-verified"); // green
  renderBadgeTo(ui, "notify", "k", "b", "zdr-policy"); // not green
  renderBadgeTo(ui, "notify", "k", "b", undefined); // unknown → treated as standard
  assert.deepEqual(levels, ["info", "warning", "warning"]);
});

test("the default sink chain prefers non-intrusive surfaces, with title last", () => {
  assert.deepEqual([...DEFAULT_BADGE_SINKS], ["status", "widget", "title"]);
  // "notify" is opt-in: a badge that fires a message on every posture change would
  // be noise, and noise is what teaches people to ignore the badge.
  assert.ok(!DEFAULT_BADGE_SINKS.includes("notify"));
});
