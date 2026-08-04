// Every option makePiPrivacyExtension() accepts, and the line between the ones a
// config file may set and the ones only code may.
//
// Kept out of extension.ts so the wiring is readable as wiring, and so config.ts can
// depend on the option SHAPE without pulling in the extension itself.

import type { PostureResult } from "./posture/verify.ts";
import type { PrivacyTier } from "./posture/tiers.ts";
import type { VerifiedTeeSignal } from "./posture/picker.ts";
import type { BadgeSink } from "./ext/badge.ts";
import type { PiCtx } from "./ext/pi-api.ts";

// ── the code-only boundary ───────────────────────────────────────────────────
// Options that may NEVER come from zero-code config (env var or JSON file). Two
// reasons, and every entry is one of them:
//
//   * it's a function — there is no JSON for a callback; and
//   * it ASSERTS something only the host can honestly assert, or SILENCES something
//     the user is meant to see. privateerVerifiedTee lifts a privacy LABEL, and
//     piiUnattended swallows a question — so only a host that genuinely operates
//     the account channel / owns the unattended state may set them, never a file
//     that arrived with a repository.
//
// This list is the single source of truth: ConfigurableOptions is derived from it,
// and config.ts warns on exactly these keys. They cannot drift apart.
export const CODE_ONLY_OPTIONS = [
  "onPosture",
  "resolveTier",
  "renderBadge",
  "privateerVerifiedTee",
  "piiUnattended",
  "renderPiiAutoRedact",
] as const;

export type CodeOnlyOption = (typeof CODE_ONLY_OPTIONS)[number];

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

// The subset of options zero-code config (env vars + JSON file) may set: everything
// except the code-only boundary above.
export type ConfigurableOptions = Omit<PiPrivacyOptions, CodeOnlyOption>;
