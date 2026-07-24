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

const POLICY3 = ["warn", "redact", "off"] as const; // piiPolicy
const TOOL_POLICY = ["warn", "block", "off"] as const; // toolExfilPolicy
const DOWNGRADE_POLICY = ["warn", "block", "off"] as const; // downgradePolicy
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
  const down = env.PI_PRIVACY_DOWNGRADE_POLICY;
  if (down) {
    const v = parseEnum("PI_PRIVACY_DOWNGRADE_POLICY", down, DOWNGRADE_POLICY, warn);
    if (v) opts.downgradePolicy = v;
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
  enumKey("downgradePolicy", DOWNGRADE_POLICY, (v) => (opts.downgradePolicy = v));

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

  for (const k of Object.keys(src)) {
    if (k === "onPosture" || k === "resolveTier" || k === "renderBadge" || k === "privateerVerifiedTee")
      warn(`config.${k} is a code-only option and can't be set from JSON — import makePiPrivacyExtension() to use it.`);
  }
  return opts;
}

export interface LoadConfigDeps {
  env?: NodeJS.ProcessEnv;
  // Injected for tests; defaults to a real synchronous file read.
  readFile?: (path: string) => string;
  cwd?: string;
  warn?: Warn;
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
  return sanitizeConfig(parsed, warn);
}
