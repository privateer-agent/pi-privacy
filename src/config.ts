// Zero-code configuration for marketplace installers.
//
// `pi install npm:pi-privacy` loads extensions/pi-privacy.ts, which builds the
// extension from loadConfig() — so a plain install can configure every non-function
// option WITHOUT writing TypeScript. Two sources, lowest → highest precedence:
//
//   1. a JSON file (PI_PRIVACY_CONFIG=<path>, else ./pi-privacy.config.json)
//   2. environment variables (PI_PRIVACY_*)
//
// env overrides the file. Only the SERIALIZABLE options are settable here; the
// function options (onPosture / resolveTier / renderBadge) are code-only and are
// reached by importing makePiPrivacyExtension() directly.
//
// Honesty carries through from the rest of the package: an invalid value is never
// silently coerced to a default that might be LESS protective than the user meant
// (a typo'd "redct" must not quietly become "warn" when they wanted "redact"). It
// warns and falls through to the built-in default, and says so.

import { readFileSync } from "node:fs";
import type { PiPrivacyOptions, BadgeSink } from "./extension.ts";

// The subset of options config can set: everything except the function callbacks and
// privateerVerifiedTee (a privacy-LABEL lever — only a host that operates the account
// channel may assert it, never a config file).
export type ConfigurableOptions = Omit<
  PiPrivacyOptions,
  "onPosture" | "resolveTier" | "renderBadge" | "privateerVerifiedTee"
>;

const POLICY3 = ["warn", "redact", "off"] as const; // piiPolicy, toolResultPolicy
const TOOL_POLICY = ["warn", "block", "off"] as const; // toolExfilPolicy
const DOWNGRADE_POLICY = ["warn", "block", "off"] as const; // downgradePolicy
const SURFACE_POLICY = ["warn", "report", "off"] as const; // toolSurfacePolicy
const SINKS: readonly BadgeSink[] = ["status", "widget", "title", "notify"];

type Warn = (msg: string) => void;

// "true/1/yes/on" → true, "false/0/no/off" → false, anything else → undefined (+warn).
function parseBool(name: string, raw: string, warn: Warn): boolean | undefined {
  const v = raw.trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(v)) return true;
  if (["0", "false", "no", "off"].includes(v)) return false;
  warn(`${name}="${raw}" is not a boolean (true/false) — ignoring, using the default.`);
  return undefined;
}

function parseEnum<T extends string>(
  name: string,
  raw: string,
  allowed: readonly T[],
  warn: Warn,
): T | undefined {
  const v = raw.trim().toLowerCase() as T;
  if (allowed.includes(v)) return v;
  warn(`${name}="${raw}" is not one of ${allowed.join("|")} — ignoring, using the default.`);
  return undefined;
}

// Comma/space separated list of badge sinks; invalid entries are dropped (+warn).
// Returns undefined (rather than []) when nothing valid is left, so the default chain
// stands instead of a badge that renders nowhere.
function parseSinks(name: string, raw: string, warn: Warn): BadgeSink[] | undefined {
  const parts = raw
    .split(/[,\s]+/)
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  const out: BadgeSink[] = [];
  for (const p of parts) {
    if ((SINKS as readonly string[]).includes(p)) out.push(p as BadgeSink);
    else warn(`${name}: "${p}" is not a badge sink (${SINKS.join("|")}) — dropping it.`);
  }
  return out.length ? out : (warn(`${name}="${raw}" has no valid sinks — using the default chain.`), undefined);
}

// A boolean-valued env var → set `key` on `opts` when present and parseable.
function boolVar(
  opts: ConfigurableOptions,
  env: NodeJS.ProcessEnv,
  name: string,
  key: keyof ConfigurableOptions,
  warn: Warn,
): void {
  const raw = env[name];
  if (raw === undefined || raw === "") return;
  const b = parseBool(name, raw, warn);
  if (b !== undefined) (opts as Record<string, unknown>)[key] = b;
}

// Read PI_PRIVACY_* environment variables into a ConfigurableOptions. Pure over `env`
// (injectable for tests). Only keys whose var is present AND valid are set.
export function optionsFromEnv(env: NodeJS.ProcessEnv, warn: Warn): ConfigurableOptions {
  const opts: ConfigurableOptions = {};

  const pii = env.PI_PRIVACY_PII_POLICY;
  if (pii) {
    const v = parseEnum("PI_PRIVACY_PII_POLICY", pii, POLICY3, warn);
    if (v) opts.piiPolicy = v;
  }
  const tool = env.PI_PRIVACY_TOOL_EXFIL_POLICY;
  if (tool) {
    const v = parseEnum("PI_PRIVACY_TOOL_EXFIL_POLICY", tool, TOOL_POLICY, warn);
    if (v) opts.toolExfilPolicy = v;
  }
  const result = env.PI_PRIVACY_TOOL_RESULT_POLICY;
  if (result) {
    const v = parseEnum("PI_PRIVACY_TOOL_RESULT_POLICY", result, POLICY3, warn);
    if (v) opts.toolResultPolicy = v;
  }
  const down = env.PI_PRIVACY_DOWNGRADE_POLICY;
  if (down) {
    const v = parseEnum("PI_PRIVACY_DOWNGRADE_POLICY", down, DOWNGRADE_POLICY, warn);
    if (v) opts.downgradePolicy = v;
  }
  const surface = env.PI_PRIVACY_TOOL_SURFACE_POLICY;
  if (surface) {
    const v = parseEnum("PI_PRIVACY_TOOL_SURFACE_POLICY", surface, SURFACE_POLICY, warn);
    if (v) opts.toolSurfacePolicy = v;
  }

  boolVar(opts, env, "PI_PRIVACY_ENFORCE_OPENROUTER_ZDR", "enforceOpenRouterZdr", warn);
  boolVar(opts, env, "PI_PRIVACY_SHOW_BADGE", "showBadge", warn);
  boolVar(opts, env, "PI_PRIVACY_INSTALL_DISPATCHER", "installDispatcher", warn);
  boolVar(opts, env, "PI_PRIVACY_REGISTER_PROVIDERS", "registerProviders", warn);
  boolVar(opts, env, "PI_PRIVACY_USE_DISPATCHER_TRANSPORT", "useDispatcherTransport", warn);
  boolVar(opts, env, "PI_PRIVACY_MODEL_PICKER", "modelPicker", warn);

  const sinks = env.PI_PRIVACY_BADGE_SINKS;
  if (sinks) {
    const v = parseSinks("PI_PRIVACY_BADGE_SINKS", sinks, warn);
    if (v) opts.badgeSinks = v;
  }
  const key = env.PI_PRIVACY_BADGE_KEY;
  if (key && key.trim()) opts.badgeKey = key.trim();
  const cmd = env.PI_PRIVACY_MODEL_PICKER_COMMAND;
  if (cmd && cmd.trim()) opts.modelPickerCommand = cmd.trim();
  const scmd = env.PI_PRIVACY_TOOL_SURFACE_COMMAND;
  if (scmd && scmd.trim()) opts.toolSurfaceCommand = scmd.trim();

  return opts;
}

// Validate a parsed JSON config object into ConfigurableOptions. Unknown keys and
// wrong-typed values are dropped (+warn) — never trusted blindly, since this drives
// what leaves the machine. The function options are rejected here too: they can't
// come from JSON, and a JSON `{"onPosture": ...}` is a mistake worth flagging.
export function sanitizeConfig(raw: unknown, warn: Warn): ConfigurableOptions {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    warn(`config file is not a JSON object — ignoring it.`);
    return {};
  }
  const src = raw as Record<string, unknown>;
  const opts: ConfigurableOptions = {};

  const enumKey = <T extends string>(k: string, allowed: readonly T[], set: (v: T) => void) => {
    if (!(k in src)) return;
    const val = src[k];
    if (typeof val === "string" && (allowed as readonly string[]).includes(val.toLowerCase()))
      set(val.toLowerCase() as T);
    else warn(`config.${k}=${JSON.stringify(val)} is not one of ${allowed.join("|")} — ignoring.`);
  };
  const boolKey = (k: keyof ConfigurableOptions) => {
    if (!(k in src)) return;
    const val = src[k as string];
    if (typeof val === "boolean") (opts as Record<string, unknown>)[k] = val;
    else warn(`config.${k as string}=${JSON.stringify(val)} is not a boolean — ignoring.`);
  };

  enumKey("piiPolicy", POLICY3, (v) => (opts.piiPolicy = v));
  enumKey("toolExfilPolicy", TOOL_POLICY, (v) => (opts.toolExfilPolicy = v));
  enumKey("toolResultPolicy", POLICY3, (v) => (opts.toolResultPolicy = v));
  enumKey("downgradePolicy", DOWNGRADE_POLICY, (v) => (opts.downgradePolicy = v));
  enumKey("toolSurfacePolicy", SURFACE_POLICY, (v) => (opts.toolSurfacePolicy = v));

  boolKey("enforceOpenRouterZdr");
  boolKey("showBadge");
  boolKey("installDispatcher");
  boolKey("registerProviders");
  boolKey("useDispatcherTransport");
  boolKey("modelPicker");

  if ("badgeSinks" in src) {
    const val = src.badgeSinks;
    if (Array.isArray(val)) {
      const out = val.filter(
        (s): s is BadgeSink => typeof s === "string" && (SINKS as readonly string[]).includes(s),
      );
      if (out.length) opts.badgeSinks = out;
      else warn(`config.badgeSinks has no valid sinks (${SINKS.join("|")}) — using the default chain.`);
    } else warn(`config.badgeSinks is not an array — ignoring.`);
  }
  if ("badgeKey" in src) {
    const val = src.badgeKey;
    if (typeof val === "string" && val.trim()) opts.badgeKey = val.trim();
    else warn(`config.badgeKey=${JSON.stringify(val)} is not a non-empty string — ignoring.`);
  }
  if ("modelPickerCommand" in src) {
    const val = src.modelPickerCommand;
    if (typeof val === "string" && val.trim()) opts.modelPickerCommand = val.trim();
    else warn(`config.modelPickerCommand=${JSON.stringify(val)} is not a non-empty string — ignoring.`);
  }
  if ("toolSurfaceCommand" in src) {
    const val = src.toolSurfaceCommand;
    if (typeof val === "string" && val.trim()) opts.toolSurfaceCommand = val.trim();
    else warn(`config.toolSurfaceCommand=${JSON.stringify(val)} is not a non-empty string — ignoring.`);
  }

  for (const k of Object.keys(src)) {
    if (k === "onPosture" || k === "resolveTier" || k === "renderBadge" || k === "privateerVerifiedTee")
      warn(`config.${k} is a code-only option and can't be set from JSON — import makePiPrivacyExtension() to use it.`);
  }
  return opts;
}

// ── the project-trust floor ──────────────────────────────────────────────────
// An implicit ./pi-privacy.config.json is PROJECT-CONTROLLED: it arrives with the
// repository you cloned, not from you. Honored blindly it is a disable switch —
// {"piiPolicy":"off","toolExfilPolicy":"off"} in a hostile repo turns off the guards
// of anyone who opens it, silently, which is the one thing this package promises
// never to do. Pi gates project-local `.pi` config behind project trust; this file
// sits outside that, so it carries its own floor.
//
// The rule: an untrusted project-local file may only make a setting MORE protective
// than the built-in default, never less. Anything that would weaken a guard is
// dropped with a warning naming it. Env vars and an explicit PI_PRIVACY_CONFIG path
// are exempt — those you typed yourself; a repo can't plant them.

// Protectiveness rank per enum option: higher = less data escapes.
const PROTECTIVENESS: Record<string, Record<string, number>> = {
  piiPolicy: { off: 0, warn: 1, redact: 2 },
  toolExfilPolicy: { off: 0, warn: 1, block: 2 },
  toolResultPolicy: { off: 0, warn: 1, redact: 2 },
  downgradePolicy: { off: 0, warn: 1, block: 2 },
  // "report" keeps the inventory but stops warning; "off" removes the axis entirely.
  // Both are weaker than the default, and this is the sharpest case the floor exists
  // for: the tool-surface axis is what reports tools THE PROJECT SUPPLIED, so a
  // project-local config turning it down is not a hypothetical attack — it is the
  // whole attack, and it would leave no trace by construction.
  toolSurfacePolicy: { off: 0, report: 1, warn: 2 },
};

// The built-in defaults the floor is measured against (mirrors makePiPrivacyExtension).
const DEFAULT_POLICY: Record<string, string> = {
  piiPolicy: "warn",
  toolExfilPolicy: "warn",
  toolResultPolicy: "warn",
  downgradePolicy: "warn",
  toolSurfacePolicy: "warn",
};

// Boolean options whose protective value is `true`. Note these are not all "guards":
// showBadge and modelPicker are VISIBILITY, and hiding the posture badge is its own
// attack — you can't notice you dropped to `standard` if nothing says so.
const PROTECTIVE_WHEN_TRUE: readonly string[] = [
  "showBadge", // hides the live posture badge
  "installDispatcher", // no dispatcher → no TLS-key binding for Tinfoil attestation
  "useDispatcherTransport", // attestation stops binding to the real inference connection
  "registerProviders", // removes the private providers from the model list
  "modelPicker", // removes the privacy-ranked picker
];

// Keys a project-local file may not set AT ALL (as opposed to "may only tighten").
// These have no protectiveness ORDERING for the rank model above to work with — any
// value is a way to hide a display, and a hidden display is indistinguishable from a
// disabled one:
//   * badgeSinks: route the badge to a surface this UI doesn't expose → nothing renders.
//   * toolSurfaceCommand: rename /surface to something the user will never type → the
//     listing still exists and is still unreachable, which is the same as gone.
//   * modelPickerCommand: the same hole in the same shape. A repo that renames /models
//     doesn't weaken any policy the ranks can measure; it just makes the privacy-ranked
//     picker unfindable, which is all it needed to do.
const PROJECT_MAY_NOT_SET: Record<string, string> = {
  badgeSinks: "a sink list can hide the posture badge",
  toolSurfaceCommand: "renaming the command can hide the tool-surface listing",
  modelPickerCommand: "renaming the command can hide the privacy-ranked model picker",
};

// Apply the floor to options parsed from an untrusted project-local config file.
// Pure; returns a copy with weakening keys dropped.
export function clampProjectConfig(opts: ConfigurableOptions, warn: Warn): ConfigurableOptions {
  const src = opts as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  const note = (key: string, val: unknown, floor: string) =>
    warn(
      `project-local pi-privacy.config.json sets ${key}=${JSON.stringify(val)}, which is WEAKER than the ` +
        `built-in default (${floor}) — ignoring it. A project you open must not be able to turn off your ` +
        `privacy guards. If you meant it, set the PI_PRIVACY_* env var, or point PI_PRIVACY_CONFIG at this file.`,
    );

  for (const [key, val] of Object.entries(src)) {
    const ranks = PROTECTIVENESS[key];
    if (ranks) {
      const floor = DEFAULT_POLICY[key];
      if ((ranks[String(val)] ?? 0) < ranks[floor]) {
        note(key, val, `"${floor}"`);
        continue;
      }
    } else if (PROTECTIVE_WHEN_TRUE.includes(key) && val === false) {
      note(key, val, "true");
      continue;
    } else if (key in PROJECT_MAY_NOT_SET) {
      warn(
        `project-local pi-privacy.config.json sets ${key} — ignoring it, since ${PROJECT_MAY_NOT_SET[key]}. ` +
          `Set the PI_PRIVACY_* env var, or point PI_PRIVACY_CONFIG at this file, if you meant it.`,
      );
      continue;
    }
    out[key] = val;
  }
  return out as ConfigurableOptions;
}

export interface LoadConfigDeps {
  env?: NodeJS.ProcessEnv;
  // Injected for tests; defaults to a real synchronous file read.
  readFile?: (path: string) => string;
  cwd?: string;
  warn?: Warn;
  // Honor an implicit ./pi-privacy.config.json in full, including settings that
  // WEAKEN the defaults (see the project-trust floor above). Default false. A host
  // that has actually resolved project trust — e.g. via Pi's project_trust event or
  // ctx.isProjectTrusted() — can pass true; nothing else should.
  projectTrusted?: boolean;
}

// The full loader used by the extension entry: file (if any) then env on top.
export function loadConfig(deps: LoadConfigDeps = {}): ConfigurableOptions {
  const env = deps.env ?? process.env;
  const warn = deps.warn ?? ((m: string) => console.warn(`[pi-privacy] ${m}`));

  const fromFile = loadFileConfig(env, deps, warn);
  const fromEnv = optionsFromEnv(env, warn);
  return { ...fromFile, ...fromEnv }; // env wins
}

function loadFileConfig(env: NodeJS.ProcessEnv, deps: LoadConfigDeps, warn: Warn): ConfigurableOptions {
  const explicit = env.PI_PRIVACY_CONFIG?.trim();
  const cwd = deps.cwd ?? process.cwd();
  const path = explicit && explicit.length ? explicit : `${cwd}/pi-privacy.config.json`;

  let text: string;
  try {
    const read = deps.readFile ?? ((p: string) => readFileSync(p, "utf8"));
    text = read(path);
  } catch (e) {
    // Only the EXPLICIT path missing is worth a warning — the default file simply
    // not existing is the common, silent case (most installs won't have one).
    if (explicit) warn(`config file "${path}" could not be read: ${(e as Error).message}`);
    return {};
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    warn(`config file "${path}" is not valid JSON: ${(e as Error).message} — ignoring it.`);
    return {};
  }
  const opts = sanitizeConfig(parsed, warn);
  // An EXPLICIT path (PI_PRIVACY_CONFIG=…) is yours — you typed it, so it's honored
  // in full. The implicit ./pi-privacy.config.json came with the project, so unless
  // the host has resolved trust it may only tighten, never weaken.
  if (explicit || deps.projectTrusted) return opts;
  return clampProjectConfig(opts, warn);
}
