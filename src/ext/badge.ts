// The live posture badge: what tier the current model resolved to, rendered to
// whichever UI surface the host actually exposes.
//
// Pure and host-agnostic — the extension owns the state (current tier, de-duping,
// the configured sink chain); this module owns only "what does a tier look like"
// and "can this UI draw it there".

import { TIERS, type PrivacyTier } from "../posture/tiers.ts";
import type { PiUi } from "./pi-api.ts";

// A UI surface the badge can render to. `status` (footer) and `widget` (line above
// the editor) are dedicated extension surfaces that don't disturb other UI; `title`
// replaces the session title (a broad-reach last resort); `notify` fires a message
// (used only on change, since the caller de-dupes). The badge walks the configured
// chain and renders to the FIRST surface the current UI actually exposes.
export type BadgeSink = "status" | "widget" | "title" | "notify";

export const DEFAULT_BADGE_SINKS: readonly BadgeSink[] = ["status", "widget", "title"];

// The status-bar badge for a tier. A glyph keyed off the traffic-light posture keeps
// verified (green 🛡) visibly distinct from asserted (yellow ⚠) and standard (• none)
// — the whole verified-vs-claimed thesis, made glanceable. `undefined` tier (not yet
// computed) shows a neutral pending marker rather than overclaiming a ceiling.
export function postureBadge(tier: PrivacyTier | undefined): string {
  if (!tier) return "⋯ checking privacy";
  const info = TIERS[tier];
  const glyph =
    info.posture === "green" ? "🛡" : info.posture === "yellow" ? "⚠" : info.posture === "red" ? "⛔" : "•";
  return `${glyph} ${info.label}`;
}

// Draw the badge to one sink. Returns false when this UI doesn't expose that surface,
// which is what lets the caller fall through to the next sink in the chain.
export function renderBadgeTo(
  ui: PiUi,
  sink: BadgeSink,
  key: string,
  badge: string,
  tier: PrivacyTier | undefined,
): boolean {
  switch (sink) {
    case "status":
      if (typeof ui.setStatus === "function") return ui.setStatus(key, badge), true;
      return false;
    case "widget":
      if (typeof ui.setWidget === "function") return ui.setWidget(key, [badge]), true;
      return false;
    case "title":
      if (typeof ui.setTitle === "function") return ui.setTitle(badge), true;
      return false;
    case "notify":
      if (typeof ui.notify === "function")
        return ui.notify(badge, TIERS[tier ?? "standard"].posture === "green" ? "info" : "warning"), true;
      return false;
    default:
      return false;
  }
}
