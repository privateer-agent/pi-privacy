// The Pi extension entry — what a marketplace install (or privateer-agent) loads.
//
// Wires the package together: installs the attestation dispatcher at extension-init
// (spike-proven to intercept provider TLS from here), registers the config-only
// privacy providers, patches venice / OpenRouter requests, tracks the current model
// to compute its posture, and adds a `/verify` command. Structural Pi typing keeps
// it decoupled from Pi's exact internal types (verified against the installed
// ExtensionAPI / ProviderConfigInput in 0.80.3).

import { installAttestationDispatcher, dispatcherTransport } from "./attest/dispatcher.ts";
import { PRIVACY_PROVIDERS, type PrivacyProvider } from "./providers/catalog.ts";
import { veniceRequestPatch, openRouterZdrPatch } from "./ext/patches.ts";
import { verifyModelPosture, type PostureResult } from "./posture/verify.ts";
import { TIERS, type PrivacyTier } from "./posture/tiers.ts";
import { effectiveTier } from "./posture/effective.ts";
import { detectPii, redactPii, summarizePii, hasSecrets, type PiiHit } from "./pii/detect.ts";
import { assessToolCall } from "./ext/toolgate.ts";
import { assessDowngrade, downgradeWarning } from "./posture/downgrade.ts";

// Verified-private tiers where PII needs no gate: an attested enclave can't read it,
// and a loopback endpoint never sends it. NOTE zdr-* is NOT here — a ZDR provider
// still SEES the data (it just doesn't retain it), so PII exposure remains.
function isVerifiedPrivate(tier: PrivacyTier | undefined): boolean {
  return tier === "tee-verified" || tier === "local";
}

// Extract the outbound message text for detection, and redact PII structurally in the
// payload's message content (string or content-part arrays).
function payloadText(payload: any): string {
  try {
    return JSON.stringify(payload?.messages ?? payload ?? "");
  } catch {
    return "";
  }
}
function redactPayloadPii(payload: any): any {
  if (!payload || typeof payload !== "object" || !Array.isArray(payload.messages)) return payload;
  const messages = payload.messages.map((m: any) => {
    if (typeof m?.content === "string") return { ...m, content: redactPii(m.content) };
    if (Array.isArray(m?.content)) {
      return {
        ...m,
        content: m.content.map((p: any) => (typeof p?.text === "string" ? { ...p, text: redactPii(p.text) } : p)),
      };
    }
    return m;
  });
  return { ...payload, messages };
}

// ── structural Pi surface (subset we use) ────────────────────────────────────
interface PiModel {
  provider?: string;
  id?: string;
}
interface PiCtx {
  hasUI?: boolean;
  ui?: {
    notify?: (message: string, level?: string) => void;
    select?: (title: string, options: string[], opts?: unknown) => Promise<string | undefined>;
    // Badge render surfaces, in descending preference. Present on event contexts (not
    // the restricted command context), and each host UI/mode may expose a different
    // subset — so every one is feature-detected before use and the badge walks a
    // fallback chain (see badgeSinks) rather than depending on any single method.
    setStatus?: (key: string, text: string | undefined) => void;
    setWidget?: (key: string, content: string[] | undefined, options?: unknown) => void;
    setTitle?: (title: string) => void;
  };
}
interface PiExtensionApiLike {
  registerProvider?(name: string, config: unknown): void;
  // Used by the downgrade guard to REVERT a model switch the user declines. Feature
  // -detected: without it the guard degrades to a warning.
  setModel?(model: unknown): boolean | Promise<boolean>;
  registerCommand?(
    name: string,
    options: { description?: string; handler: (args: unknown, ctx: PiCtx) => unknown },
  ): void;
  on(event: string, handler: (event: any, ctx: PiCtx) => any): void;
}

export interface PiPrivacyOptions {
  // Install the process-wide attestation dispatcher (default true). Set false if the
  // host already installed one (e.g. privateer-agent's boot.ts).
  installDispatcher?: boolean;
  // Register the config-only privacy providers (tinfoil/nearai/venice/ollama/
  // privateer-api) with seed models (default true). Built-in providers
  // (openrouter/fireworks) are left
  // to Pi so their model listings aren't clobbered.
  registerProviders?: boolean;
  // Enforce OpenRouter ZDR routing (default false — opt-in, since a model with no
  // zero-retention endpoint will 404 rather than fall back). VERIFIED honest: when
  // on, requests carry provider.{zdr:true,data_collection:"deny"}, which OpenRouter
  // observably enforces (it 404s if unsatisfiable), so the zdr-enforced badge is earned.
  enforceOpenRouterZdr?: boolean;
  // Called whenever the current model's posture is (re)computed — the badge feed.
  onPosture?: (result: PostureResult) => void;
  // Bind Tinfoil attestation to the real provider connection via the dispatcher
  // (default true when the dispatcher is installed). Falls back to httpsTransport.
  useDispatcherTransport?: boolean;
  // Override the tier resolution for providers pi-privacy doesn't know (e.g. a host's
  // private account channel). Return a PrivacyTier to use it (drives the PII gate +
  // badge), or undefined to fall back to pi-privacy's built-in verified posture.
  resolveTier?: (provider: string, modelId: string) => Promise<PrivacyTier | undefined> | PrivacyTier | undefined;
  // Posture-aware structured-PII policy on outbound requests. "warn" (default):
  // interactively warn + offer redact before sending PII down an UNVERIFIED channel;
  // "redact": silently mask; "off": disabled. Only acts below verified-TEE/local
  // (an attested/on-device channel is safe), and only where a UI can prompt. Detection
  // is best-effort structured PII + secrets (emails/phones/SSNs/cards/IPs, API keys/
  // tokens/private keys) — NOT a guarantee.
  piiPolicy?: "warn" | "redact" | "off";
  // Show the live posture badge (default true). Updates on model switch + each request
  // so "verified vs asserted" is always glanceable, never on-demand-only.
  showBadge?: boolean;
  // Ordered fallback chain of UI surfaces for the badge. The FIRST one the current UI
  // actually exposes is used, so the badge still renders across host UIs/modes that
  // support different methods (not every context has setStatus). Default:
  // ["status","widget","title"] — the non-intrusive surfaces first, title as a
  // broad-reach last resort. Add "notify" to also surface changes as messages.
  badgeSinks?: BadgeSink[];
  // The key the badge writes under (setStatus/setWidget are keyed) so a host can
  // namespace or replace it. Default "pi-privacy".
  badgeKey?: string;
  // Fully custom badge renderer — overrides the sink chain entirely. Receives the
  // computed badge text, the tier, and the current context. Use to route the badge
  // anywhere (a custom widget, an external status line, telemetry).
  renderBadge?: (badge: string, tier: PrivacyTier | undefined, ctx: PiCtx) => void;
  // Guard PII/secrets leaving the machine via a TOOL call (bash curl, web-fetch, an
  // MCP tool, …) — ORTHOGONAL to model posture (a TEE/ZDR model doesn't stop a tool
  // exfiltrating data to a third party). "warn" (default): interactively confirm
  // before an egress tool call carrying PII/secrets; "block": always block such calls;
  // "off": disabled. In warn mode with no UI, a CREDENTIAL leak is blocked (loud +
  // safe) while mere PII is allowed with a notice.
  toolExfilPolicy?: "warn" | "block" | "off";
  // Guard against a POSTURE DOWNGRADE: switching to a weaker-tier model re-sends the
  // whole accumulated session history — everything the private channel was
  // protecting — to the new provider on the very next turn. No per-request gate can
  // see this, because nothing about the request changed; only the transition reveals
  // it. "warn" (default): prompt when the tier drops and the context is known to
  // carry PII/secrets, offering to revert the switch; "block": always revert such a
  // switch; "off": disabled. With no UI, a downgrade carrying CREDENTIALS is
  // reverted (mirroring the tool gate's loud-and-safe default), mere PII notified.
  downgradePolicy?: "warn" | "block" | "off";
}

// Config-only providers Pi doesn't ship: register these. Built-ins + custom skipped.
const BUILTIN = new Set(["openrouter", "fireworks"]);
const SEED_MODELS: Record<string, string> = {
  tinfoil: "deepseek-v4-pro",
  nearai: "zai-org/GLM-5.1-FP8",
  venice: "qwen3-coder-480b-a35b-instruct-turbo",
  ollama: "llama3.1",
  "privateer-api": "near/zai-org/GLM-5.1-FP8",
};

function registerable(p: PrivacyProvider): boolean {
  return !!p.baseUrl && !BUILTIN.has(p.id) && p.id !== "custom";
}

// The status-bar badge for a tier. A glyph keyed off the traffic-light posture keeps
// verified (green 🛡) visibly distinct from asserted (yellow ⚠) and standard (• none)
// — the whole verified-vs-claimed thesis, made glanceable. `undefined` tier (not yet
// computed) shows a neutral pending marker rather than overclaiming a ceiling.
function postureBadge(tier: PrivacyTier | undefined): string {
  if (!tier) return "⋯ checking privacy";
  const info = TIERS[tier];
  const glyph =
    info.posture === "green" ? "🛡" : info.posture === "yellow" ? "⚠" : info.posture === "red" ? "⛔" : "•";
  return `${glyph} ${info.label}`;
}

// A UI surface the badge can render to. `status` (footer) and `widget` (line above
// the editor) are dedicated extension surfaces that don't disturb other UI; `title`
// replaces the session title (a broad-reach last resort); `notify` fires a message
// (used only on change, since paintBadge de-dupes). The badge walks the configured
// chain and renders to the FIRST surface the current UI actually exposes.
export type BadgeSink = "status" | "widget" | "title" | "notify";

function renderBadgeTo(
  ui: NonNullable<PiCtx["ui"]>,
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

function providerConfig(p: PrivacyProvider): unknown {
  const seed = SEED_MODELS[p.id];
  const models = seed
    ? [
        {
          id: seed,
          name: seed,
          reasoning: false,
          input: ["text"] as ("text" | "image")[],
          cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
          contextWindow: 128000,
          maxTokens: 4096,
        },
      ]
    : [];
  const cfg: Record<string, unknown> = { name: p.label, baseUrl: p.baseUrl, api: p.api, models };
  if (p.keyEnv) {
    cfg.apiKey = p.keyEnv; // env template ${...}; Pi resolves it
    cfg.authHeader = true;
  } else if (p.local && models.length) {
    // Pi requires apiKey (or oauth) whenever a provider defines models. Local
    // servers (ollama) ignore the auth header, so a placeholder satisfies the
    // validation without sending a meaningful credential.
    cfg.apiKey = "local";
  }
  return cfg;
}

function nearApiKey(): string | undefined {
  // Both spellings are used in the wild (see privateer redact.ts).
  return process.env.NEARAI_API_KEY ?? process.env.NEAR_AI_API_KEY;
}

export function makePiPrivacyExtension(opts: PiPrivacyOptions = {}) {
  const {
    installDispatcher = true,
    registerProviders = true,
    enforceOpenRouterZdr = false,
    onPosture,
    useDispatcherTransport = true,
    piiPolicy = "warn",
    showBadge = true,
    badgeSinks = ["status", "widget", "title"],
    badgeKey = "pi-privacy",
    renderBadge,
    toolExfilPolicy = "warn",
    downgradePolicy = "warn",
    resolveTier,
  } = opts;

  return function piPrivacy(pi: PiExtensionApiLike): void {
    if (installDispatcher) installAttestationDispatcher();

    if (registerProviders && typeof pi.registerProvider === "function") {
      for (const p of PRIVACY_PROVIDERS) {
        if (registerable(p)) pi.registerProvider(p.id, providerConfig(p));
      }
    }

    let currentProviderId: string | undefined;
    let currentModelId: string | undefined;
    // The VERIFIED tier of the current model (attestation result), cached for the PII
    // gate. Undefined until computed → the gate treats "unknown" as not-verified (safe).
    let currentTier: PrivacyTier | undefined;
    // Session PII decision so we don't re-prompt every turn once the user has chosen.
    let piiChoice: "ask" | "send" | "redact" = "ask";
    // Session decision for the tool-exfil gate (allow egress with sensitive data).
    let toolAllow = false;

    // ── downgrade-guard state ────────────────────────────────────────────────
    // The tier the accumulated context was protected by at the moment of the last
    // switch, and the model to hand back to pi.setModel() if the user declines.
    let previousTier: PrivacyTier | undefined;
    let previousModel: unknown;
    // One prompt per transition: the guard runs twice (on the switch, using the new
    // model's ceiling, then again once attestation resolves the real tier, which can
    // only be lower). This latches after the first one that actually fires.
    let downgradeHandled = true;
    // What the last outbound payload was known to carry. Cached on EVERY request —
    // including verified-private ones, where the PII gate itself is skipped —
    // precisely so the guard knows what a private session accumulated before the
    // switch. Scanning is local, deterministic, and a few ms even on a full context.
    let contextHits: PiiHit[] = [];

    // The latest UI surface we've seen — captured from event contexts (the command
    // context is restricted), so refreshPosture() can paint the badge even though
    // model_select fires it without threading ctx through. `lastBadge` de-dupes so an
    // unchanged posture never re-renders (keeps a "notify" sink from spamming).
    let lastUi: NonNullable<PiCtx["ui"]> | undefined;
    let lastCtx: PiCtx | undefined;
    let lastBadge: string | undefined;
    // Whether the host can actually prompt. Captured alongside the UI because
    // guards that run detached from an event (the downgrade guard's second pass,
    // after attestation resolves) have no ctx of their own — and treating a TUI as
    // non-interactive would silently apply the no-UI fallback instead of asking.
    let lastHasUI = false;
    const captureUi = (ctx: PiCtx | undefined) => {
      if (ctx?.ui) ((lastUi = ctx.ui), (lastCtx = ctx), (lastHasUI = !!ctx.hasUI));
    };
    const paintBadge = () => {
      if (!showBadge || !lastUi) return;
      const badge = postureBadge(currentTier);
      if (badge === lastBadge) return; // unchanged → no-op
      let rendered = false;
      if (renderBadge) ((renderBadge(badge, currentTier, lastCtx!)), (rendered = true));
      else {
        for (const sink of badgeSinks) {
          if (renderBadgeTo(lastUi, sink, badgeKey, badge, currentTier)) {
            rendered = true;
            break;
          }
        }
      }
      if (rendered) lastBadge = badge; // only commit once something actually drew it
    };

    // Recompute posture for the current model; cache the tier and publish the badge.
    const refreshPosture = async () => {
      if (!currentProviderId || !currentModelId) return;
      // A host-supplied resolver (e.g. a private account channel pi-privacy doesn't
      // know) wins — otherwise use the built-in verified posture.
      if (resolveTier) {
        const t = await resolveTier(currentProviderId, currentModelId);
        if (t !== undefined) {
          currentTier = t;
          onPosture?.({ providerId: currentProviderId, modelId: currentModelId, tier: t });
          paintBadge();
          void guardDowngrade(t);
          return;
        }
      }
      const result = await verifyModelPosture(currentProviderId, currentModelId, {
        apiKey: currentProviderId === "nearai" ? nearApiKey() : undefined,
        zdrEnforced: currentProviderId === "openrouter" && enforceOpenRouterZdr,
        transport: useDispatcherTransport && installDispatcher ? dispatcherTransport : undefined,
      });
      currentTier = result.tier;
      onPosture?.(result);
      paintBadge();
      // Re-check with the VERIFIED tier: a model whose ceiling looked fine can land
      // lower (attestation failed → tee-unverified), and that's still a downgrade.
      void guardDowngrade(result.tier);
    };

    // The posture-downgrade guard. Runs on a model switch and again once attestation
    // resolves, because the incoming tier can only get WORSE than its ceiling.
    // Fires only when the tier actually drops AND the context is known to carry
    // sensitive material — a bare tier change is what the badge is for.
    const guardDowngrade = async (toTier: PrivacyTier | undefined, ctx?: PiCtx) => {
      if (downgradePolicy === "off" || downgradeHandled) return;
      const a = assessDowngrade(previousTier, toTier, contextHits);
      if (!a.downgrade || a.severity === "none") return;
      downgradeHandled = true; // one prompt per transition

      const label = currentProviderId
        ? `${currentProviderId}${currentModelId ? `/${currentModelId}` : ""}`
        : undefined;
      const warning = downgradeWarning(a, contextHits, label);
      const revert = async () => {
        if (previousModel === undefined || typeof pi.setModel !== "function") {
          // Nothing to revert to (or the host can't switch) — say so rather than
          // implying the session was protected.
          (ctx?.ui ?? lastUi)?.notify?.(`${warning} Could not revert the switch automatically.`, "warning");
          return;
        }
        await pi.setModel(previousModel);
        (ctx?.ui ?? lastUi)?.notify?.(`Reverted to ${TIERS[a.from].label} — session context stays put.`, "info");
      };

      if (downgradePolicy === "block") return revert();

      const ui = ctx?.ui ?? lastUi;
      if ((ctx?.hasUI ?? lastHasUI) && typeof ui?.select === "function") {
        const choice = await ui.select(warning, [
          "Stay on the previous model",
          "Switch anyway",
          "Switch, redacting PII from now on",
        ]);
        if (choice === "Switch anyway") return;
        if (choice === "Switch, redacting PII from now on") {
          piiChoice = "redact";
          return;
        }
        return revert(); // explicit "Stay", or cancelled → the safe default
      }

      // No UI (print/JSON, automated): mirror the tool gate — a CREDENTIAL following
      // the session downhill is reverted (loud + safe), mere PII passes with a notice.
      if (a.severity === "secret") return revert();
      ui?.notify?.(warning, "warning");
    };

    pi.on("model_select", (event, ctx) => {
      const model = event?.model as PiModel | undefined;
      // Snapshot what the context was protected by BEFORE overwriting it — that's
      // the ceiling the accumulated history was written under.
      previousTier = currentTier;
      previousModel = event?.previousModel;
      downgradeHandled = false; // arm the guard for this transition
      currentProviderId = model?.provider;
      currentModelId = model?.id;
      captureUi(ctx);
      currentTier = undefined; // don't show the old model's badge while re-verifying
      paintBadge(); // pending marker until attestation resolves
      // Check against the incoming model's CEILING immediately, so the warning lands
      // before a turn can start; refreshPosture() re-checks with the verified tier.
      void guardDowngrade(
        effectiveTier(currentProviderId ?? "", {
          zdrEnforced: currentProviderId === "openrouter" && enforceOpenRouterZdr,
        }),
        ctx,
      );
      void refreshPosture();
    });

    // Per-provider request patches + the posture-aware PII gate.
    pi.on("before_provider_request", async (event, ctx) => {
      captureUi(ctx); // keep the badge alive even if model_select had no UI
      paintBadge();
      let payload = event?.payload;
      // Provider-specific patches first (scoped to the current provider).
      if (currentProviderId === "venice") payload = veniceRequestPatch(payload);
      else if (currentProviderId === "openrouter" && enforceOpenRouterZdr) payload = openRouterZdrPatch(payload);

      // Scan the outbound payload — the full context that would be re-sent — and
      // cache the result for the downgrade guard. Done for EVERY tier, including
      // verified-private ones where the gate below is skipped: knowing what a
      // private session accumulated is the whole basis for guarding the switch out
      // of it. (Local + deterministic; a few ms on a full context.)
      const hits = detectPii(payloadText(payload));
      contextHits = hits;

      // PII gate: only below a VERIFIED-private tier (TEE-verified/local are safe —
      // the provider can't read the data), and only where we can actually prompt.
      if (piiPolicy !== "off" && !isVerifiedPrivate(currentTier)) {
        if (hits.length > 0) {
          let action: "send" | "redact" =
            piiChoice !== "ask" ? piiChoice : piiPolicy === "redact" ? "redact" : "send";
          if (piiChoice === "ask" && piiPolicy === "warn" && ctx?.hasUI && typeof ctx.ui?.select === "function") {
            const tierLabel = TIERS[currentTier ?? "standard"].label;
            const kind = hasSecrets(hits) ? "secrets/PII" : "structured PII";
            const choice = await ctx.ui.select(
              `⚠ ${summarizePii(hits)} detected — sending to an unverified channel (${tierLabel}). ` +
                `Best-effort ${kind} detection only, not a guarantee.`,
              ["Send as-is", "Redact PII", "Redact + remember for session", "Send + remember for session"],
            );
            if (choice === "Redact PII") action = "redact";
            else if (choice === "Redact + remember for session") ((action = "redact"), (piiChoice = "redact"));
            else if (choice === "Send + remember for session") ((action = "send"), (piiChoice = "send"));
            else action = "send"; // "Send as-is" or cancelled
          }
          if (action === "redact") payload = redactPayloadPii(payload);
        }
      }

      return payload === event?.payload ? undefined : payload;
    });

    // Tool-exfil gate: warn/block PII or secrets about to leave the machine via a TOOL
    // call. Deliberately INDEPENDENT of the model's tier — a verified-TEE or ZDR model
    // does nothing to stop a bash/web tool shipping data to a third party. Best-effort
    // egress + structured-detection heuristic, never a guarantee.
    pi.on("tool_call", async (event, ctx) => {
      if (toolExfilPolicy === "off") return;
      captureUi(ctx);
      const assessment = assessToolCall(event?.toolName, event?.input);
      if (!assessment.egress) return;

      const hits = detectPii(payloadText(event?.input));
      if (hits.length === 0) return;

      const secret = hasSecrets(hits);
      const dest = assessment.target ? ` → ${assessment.target}` : "";
      const summary = summarizePii(hits);
      const reason = `pi-privacy blocked ${secret ? "credential" : "PII"} exfiltration via ${event?.toolName}`;
      const warning =
        `⚠ ${event?.toolName} is about to send ${summary} off this machine${dest}. ` +
        `A private (TEE/ZDR) model does NOT protect a tool call. Best-effort detection, not a guarantee.`;

      // Already allowed this session → just remind and let it through.
      if (toolAllow) {
        ctx?.ui?.notify?.(warning, "warning");
        return;
      }
      if (toolExfilPolicy === "block") return { block: true, reason };

      // warn: prompt where we can.
      if (ctx?.hasUI && typeof ctx.ui?.select === "function") {
        const choice = await ctx.ui.select(warning, ["Block", "Allow once", "Allow for session"]);
        if (choice === "Allow for session") ((toolAllow = true), undefined);
        else if (choice === "Allow once") return;
        else if (choice === "Block" || choice === undefined) return { block: true, reason };
        return;
      }

      // No UI (print/JSON, automated): block a credential leak (loud + safe); allow
      // mere PII with a notice so non-interactive runs aren't silently broken.
      if (secret) return { block: true, reason };
      ctx?.ui?.notify?.(warning, "warning");
      return;
    });

    if (typeof pi.registerCommand === "function") {
      pi.registerCommand("verify", {
        description: "Verify the current model's privacy posture (TEE attestation)",
        handler: async (_args, ctx) => {
          if (!currentProviderId || !currentModelId) {
            ctx.ui?.notify?.("No model selected.", "warning");
            return;
          }
          const res = await verifyModelPosture(currentProviderId, currentModelId, {
            apiKey: currentProviderId === "nearai" ? nearApiKey() : undefined,
            zdrEnforced: currentProviderId === "openrouter" && enforceOpenRouterZdr,
            transport: useDispatcherTransport && installDispatcher ? dispatcherTransport : undefined,
          });
          const info = TIERS[res.tier];
          const detail = res.teePosture ? ` [${res.teePosture}]` : "";
          const err = res.error ? ` — ${res.error}` : "";
          ctx.ui?.notify?.(`${info.label}${detail}: ${info.blurb}${err}`, "info");
          // Then the EVIDENCE. The checks here are pragmatic ones suited to an
          // interactive agent, not a full verifier — so the report that produced
          // the verdict has to be inspectable, or "verified" is just our word for
          // it. Emitting it is what lets a user take the same bytes to
          // nearai/cloud-verifier or tinfoil-cli and check our work.
          if (res.attestation !== undefined) {
            let report: string;
            try {
              report = JSON.stringify(res.attestation, null, 2);
            } catch {
              report = String(res.attestation); // never let display kill /verify
            }
            ctx.ui?.notify?.(`attestation report (verify independently):\n${report}`, "info");
          }
        },
      });
    }
  };
}

// Default export: the marketplace-installable extension with default options.
export default makePiPrivacyExtension();
