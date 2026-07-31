import { test } from "node:test";
import assert from "node:assert/strict";
import { optionsFromEnv, sanitizeConfig, loadConfig, clampProjectConfig } from "../src/config.ts";

// A warn collector so we can assert honest-failure behavior (invalid values warn +
// fall through to the default rather than silently coercing).
function collector() {
  const msgs: string[] = [];
  return { warn: (m: string) => msgs.push(m), msgs };
}

test("optionsFromEnv reads and validates the policy + bool vars", () => {
  const { warn, msgs } = collector();
  const opts = optionsFromEnv(
    {
      PI_PRIVACY_PII_POLICY: "redact",
      PI_PRIVACY_TOOL_EXFIL_POLICY: "block",
      PI_PRIVACY_DOWNGRADE_POLICY: "off",
      PI_PRIVACY_ENFORCE_OPENROUTER_ZDR: "true",
      PI_PRIVACY_SHOW_BADGE: "0",
      PI_PRIVACY_BADGE_KEY: "  my-key  ",
    } as NodeJS.ProcessEnv,
    warn,
  );
  assert.deepEqual(opts, {
    piiPolicy: "redact",
    toolExfilPolicy: "block",
    downgradePolicy: "off",
    enforceOpenRouterZdr: true,
    showBadge: false,
    badgeKey: "my-key",
  });
  assert.equal(msgs.length, 0);
});

test("optionsFromEnv reads the model-picker toggle + command name", () => {
  const { warn, msgs } = collector();
  const opts = optionsFromEnv(
    {
      PI_PRIVACY_MODEL_PICKER: "off",
      PI_PRIVACY_MODEL_PICKER_COMMAND: "  privacy-models  ",
    } as NodeJS.ProcessEnv,
    warn,
  );
  assert.deepEqual(opts, { modelPicker: false, modelPickerCommand: "privacy-models" });
  assert.equal(msgs.length, 0);
});

test("sanitizeConfig accepts modelPicker (bool) + modelPickerCommand (string)", () => {
  const { warn } = collector();
  assert.deepEqual(
    sanitizeConfig({ modelPicker: true, modelPickerCommand: "pm" }, warn),
    { modelPicker: true, modelPickerCommand: "pm" },
  );
});

test("an invalid enum warns and is left unset (never coerced to a default)", () => {
  const { warn, msgs } = collector();
  const opts = optionsFromEnv({ PI_PRIVACY_PII_POLICY: "redct" } as NodeJS.ProcessEnv, warn);
  assert.equal("piiPolicy" in opts, false); // NOT silently "warn"
  assert.equal(msgs.length, 1);
  assert.match(msgs[0], /PII_POLICY/);
});

test("an unparseable bool warns and is ignored", () => {
  const { warn, msgs } = collector();
  const opts = optionsFromEnv({ PI_PRIVACY_ENFORCE_OPENROUTER_ZDR: "maybe" } as NodeJS.ProcessEnv, warn);
  assert.deepEqual(opts, {});
  assert.match(msgs[0], /not a boolean/);
});

test("badge sinks parse, drop invalid entries, and fall back when empty", () => {
  const { warn } = collector();
  assert.deepEqual(
    optionsFromEnv({ PI_PRIVACY_BADGE_SINKS: "status, notify, bogus" } as NodeJS.ProcessEnv, warn).badgeSinks,
    ["status", "notify"],
  );
  const { warn: w2, msgs } = collector();
  const opts = optionsFromEnv({ PI_PRIVACY_BADGE_SINKS: "bogus,nope" } as NodeJS.ProcessEnv, w2);
  assert.equal("badgeSinks" in opts, false); // no valid sinks → default chain stands
  assert.ok(msgs.some((m) => /no valid sinks/.test(m)));
});

test("sanitizeConfig validates types and rejects code-only + unknown keys", () => {
  const { warn, msgs } = collector();
  const opts = sanitizeConfig(
    {
      piiPolicy: "warn",
      showBadge: true,
      enforceOpenRouterZdr: "yes", // wrong type → dropped
      badgeSinks: ["widget", "nope"],
      onPosture: {}, // code-only → rejected + warned
    },
    warn,
  );
  assert.deepEqual(opts, { piiPolicy: "warn", showBadge: true, badgeSinks: ["widget"] });
  assert.ok(msgs.some((m) => /enforceOpenRouterZdr/.test(m) && /boolean/.test(m)));
  assert.ok(msgs.some((m) => /onPosture/.test(m) && /code-only/.test(m)));
});

test("sanitizeConfig rejects a non-object", () => {
  const { warn, msgs } = collector();
  assert.deepEqual(sanitizeConfig([1, 2, 3], warn), {});
  assert.match(msgs[0], /not a JSON object/);
});

test("loadConfig layers env OVER the file", () => {
  // Tightening/neutral values only — a project-local file that WEAKENS a default is
  // dropped by the trust floor (covered below), which would confound this test.
  const readFile = () => JSON.stringify({ piiPolicy: "redact", toolExfilPolicy: "block", badgeKey: "k" });
  const opts = loadConfig({
    env: { PI_PRIVACY_PII_POLICY: "warn" } as NodeJS.ProcessEnv,
    readFile,
    warn: () => {},
  });
  // file supplies toolExfilPolicy/badgeKey; env overrides piiPolicy.
  assert.deepEqual(opts, { piiPolicy: "warn", toolExfilPolicy: "block", badgeKey: "k" });
});

test("loadConfig is silent when the default config file is absent", () => {
  const { warn, msgs } = collector();
  const readFile = () => {
    throw new Error("ENOENT");
  };
  const opts = loadConfig({ env: {} as NodeJS.ProcessEnv, readFile, warn });
  assert.deepEqual(opts, {});
  assert.equal(msgs.length, 0); // a missing DEFAULT file is the common case, not a warning
});

test("loadConfig warns when an EXPLICIT config path can't be read", () => {
  const { warn, msgs } = collector();
  const readFile = () => {
    throw new Error("ENOENT");
  };
  loadConfig({ env: { PI_PRIVACY_CONFIG: "/nope/pi.json" } as NodeJS.ProcessEnv, readFile, warn });
  assert.match(msgs[0], /could not be read/);
});

test("loadConfig warns on malformed JSON and ignores the file", () => {
  const { warn, msgs } = collector();
  const opts = loadConfig({
    env: { PI_PRIVACY_CONFIG: "/x/pi.json" } as NodeJS.ProcessEnv,
    readFile: () => "{ not json",
    warn,
  });
  assert.deepEqual(opts, {});
  assert.match(msgs[0], /not valid JSON/);
});

// ── the project-trust floor ──────────────────────────────────────────────────
// An implicit ./pi-privacy.config.json arrives with the repository you cloned, not
// from you. Honored blindly it is a disable switch for anyone who opens the project.

test("a project-local config cannot turn the guards off", () => {
  const { warn, msgs } = collector();
  const readFile = () =>
    JSON.stringify({
      piiPolicy: "off",
      toolExfilPolicy: "off",
      toolResultPolicy: "off",
      downgradePolicy: "off",
      showBadge: false,
      installDispatcher: false,
      useDispatcherTransport: false,
    });
  const opts = loadConfig({ env: {} as NodeJS.ProcessEnv, readFile, warn });
  assert.deepEqual(opts, {}, "every weakening setting dropped");
  assert.equal(msgs.length, 7, "and each one named, not silently ignored");
  assert.ok(msgs.every((m) => /WEAKER than the built-in default/.test(m)));
  assert.ok(msgs[0].includes("PI_PRIVACY_CONFIG"), "says how to opt in if you meant it");
});

test("a project-local config CAN tighten — the floor is one-directional", () => {
  const { warn, msgs } = collector();
  const readFile = () =>
    JSON.stringify({ piiPolicy: "redact", toolExfilPolicy: "block", enforceOpenRouterZdr: true, badgeKey: "k" });
  const opts = loadConfig({ env: {} as NodeJS.ProcessEnv, readFile, warn });
  assert.deepEqual(opts, {
    piiPolicy: "redact",
    toolExfilPolicy: "block",
    enforceOpenRouterZdr: true,
    badgeKey: "k",
  });
  assert.equal(msgs.length, 0, "tightening is never second-guessed");
});

test("a project-local config cannot hide the posture badge", () => {
  const { warn, msgs } = collector();
  // Not a guard, but its own attack: you can't notice you dropped to `standard` if
  // nothing says so. A sink list can silently render the badge nowhere.
  const readFile = () => JSON.stringify({ badgeSinks: ["notify"], modelPicker: false });
  const opts = loadConfig({ env: {} as NodeJS.ProcessEnv, readFile, warn });
  assert.deepEqual(opts, {});
  assert.equal(msgs.length, 2);
  assert.ok(msgs.some((m) => /can hide the\s+posture badge/.test(m)));
});

test("an EXPLICIT config path is yours — honored in full, floor and all", () => {
  const { warn, msgs } = collector();
  const readFile = () => JSON.stringify({ piiPolicy: "off", showBadge: false });
  const opts = loadConfig({
    env: { PI_PRIVACY_CONFIG: "/home/me/my-pi-privacy.json" } as NodeJS.ProcessEnv,
    readFile,
    warn,
  });
  assert.deepEqual(opts, { piiPolicy: "off", showBadge: false }, "you typed the path; a repo can't plant it");
  assert.equal(msgs.length, 0);
});

test("a host that has resolved project trust can opt back in", () => {
  const readFile = () => JSON.stringify({ piiPolicy: "off" });
  const opts = loadConfig({ env: {} as NodeJS.ProcessEnv, readFile, warn: () => {}, projectTrusted: true });
  assert.deepEqual(opts, { piiPolicy: "off" });
});

test("env vars are never clamped — a repo cannot set them", () => {
  const { warn, msgs } = collector();
  const opts = loadConfig({
    env: { PI_PRIVACY_PII_POLICY: "off", PI_PRIVACY_SHOW_BADGE: "false" } as NodeJS.ProcessEnv,
    readFile: () => {
      throw new Error("ENOENT");
    },
    warn,
  });
  assert.deepEqual(opts, { piiPolicy: "off", showBadge: false });
  assert.equal(msgs.length, 0);
});

// ── the tool-surface axis: config + the project-trust floor ──────────────────

test("toolSurfacePolicy + toolSurfaceCommand are settable from env and JSON", () => {
  const msgs: string[] = [];
  const warn = (m: string) => msgs.push(m);
  assert.deepEqual(
    optionsFromEnv(
      { PI_PRIVACY_TOOL_SURFACE_POLICY: "report", PI_PRIVACY_TOOL_SURFACE_COMMAND: " whoelse " } as any,
      warn,
    ),
    { toolSurfacePolicy: "report", toolSurfaceCommand: "whoelse" },
  );
  assert.deepEqual(sanitizeConfig({ toolSurfacePolicy: "off", toolSurfaceCommand: "surface" }, warn), {
    toolSurfacePolicy: "off",
    toolSurfaceCommand: "surface",
  });
  assert.equal(msgs.length, 0);
});

test("toolSurfacePolicy: an invalid value falls back loudly, never quietly", () => {
  const msgs: string[] = [];
  assert.deepEqual(optionsFromEnv({ PI_PRIVACY_TOOL_SURFACE_POLICY: "quiet" } as any, (m) => msgs.push(m)), {});
  assert.match(msgs[0], /warn\|report\|off/);
});

// The sharpest case the floor exists for. The tool-surface axis reports tools
// supplied BY THE PROJECT — so a project-local config turning it down isn't a
// hypothetical attack, it's the whole attack, and it would leave no trace.
test("floor: a project-local config cannot turn down the tool-surface axis", () => {
  for (const weaker of ["off", "report"]) {
    const msgs: string[] = [];
    assert.deepEqual(clampProjectConfig({ toolSurfacePolicy: weaker } as any, (m) => msgs.push(m)), {});
    assert.match(msgs[0], /toolSurfacePolicy/);
    assert.match(msgs[0], /WEAKER/);
  }
  // Tightening — here, the default — is never second-guessed.
  assert.deepEqual(clampProjectConfig({ toolSurfacePolicy: "warn" }, () => {}), {
    toolSurfacePolicy: "warn",
  });
});

// The same hole in the same shape as toolSurfaceCommand: a repo that renames /models
// weakens no policy the ranks can measure, it just makes the privacy-ranked picker
// unfindable — which is all it needed to do.
test("floor: a project-local config cannot rename the /models picker either", () => {
  const msgs: string[] = [];
  assert.deepEqual(clampProjectConfig({ modelPickerCommand: "zzz" }, (m) => msgs.push(m)), {});
  assert.match(msgs[0], /modelPickerCommand/);
  assert.match(msgs[0], /can hide the privacy-ranked model picker/);
});

// Renaming the command hides the listing just as effectively as disabling it, and a
// rename has no protectiveness ordering for the floor's rank model to work with.
test("floor: a project-local config cannot rename the /surface command", () => {
  const msgs: string[] = [];
  const out = clampProjectConfig({ toolSurfaceCommand: "zzz" }, (m) => msgs.push(m));
  assert.deepEqual(out, {});
  assert.match(msgs[0], /toolSurfaceCommand/);
  assert.match(msgs[0], /can hide the tool-surface listing/);
});

// An allowlist only ever REMOVES detection, so a repo you cloned may not add one:
// {"piiAllow":["*@*"]} would be piiPolicy:"off" for exactly that repo's data, and it
// would read as a gate that honestly found nothing.
test("floor: a project-local config cannot add PII allowlist entries", () => {
  const msgs: string[] = [];
  assert.deepEqual(clampProjectConfig({ piiAllow: ["@acme.com"] }, (m) => msgs.push(m)), {});
  assert.match(msgs[0], /piiAllow/);
  assert.match(msgs[0], /can hide PII from the gate/);
  // Turning the built-in defaults OFF is a tightening, so it survives the floor.
  assert.deepEqual(clampProjectConfig({ piiAllowDefaults: false }, () => {}), { piiAllowDefaults: false });
});

test("piiAllow: parsed from JSON and env, junk entries dropped with a warning", () => {
  const msgs: string[] = [];
  assert.deepEqual(sanitizeConfig({ piiAllow: ["@acme.com", 7, "  "] }, (m) => msgs.push(m)).piiAllow, ["@acme.com"]);
  assert.match(msgs[0], /piiAllow/);
  assert.deepEqual(sanitizeConfig({ piiAllow: "@acme.com" }, () => {}).piiAllow, undefined);
  assert.deepEqual(
    optionsFromEnv({ PI_PRIVACY_PII_ALLOW: "@acme.com, 10.0.0.0/8 me@x.io" } as NodeJS.ProcessEnv, () => {}).piiAllow,
    ["@acme.com", "10.0.0.0/8", "me@x.io"],
  );
  assert.equal(
    optionsFromEnv({ PI_PRIVACY_PII_ALLOW_DEFAULTS: "false" } as NodeJS.ProcessEnv, () => {}).piiAllowDefaults,
    false,
  );
});

test("floor: the badgeSinks rule still names itself after the refactor", () => {
  const msgs: string[] = [];
  assert.deepEqual(clampProjectConfig({ badgeSinks: ["notify"] } as any, (m) => msgs.push(m)), {});
  assert.match(msgs[0], /badgeSinks/);
  assert.match(msgs[0], /can hide the posture badge/);
});
