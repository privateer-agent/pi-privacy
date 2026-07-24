import { test } from "node:test";
import assert from "node:assert/strict";
import { optionsFromEnv, sanitizeConfig, loadConfig } from "../src/config.ts";

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
  const readFile = () => JSON.stringify({ piiPolicy: "off", toolExfilPolicy: "block", showBadge: false });
  const opts = loadConfig({
    env: { PI_PRIVACY_PII_POLICY: "redact" } as NodeJS.ProcessEnv,
    readFile,
    warn: () => {},
  });
  // file supplies toolExfilPolicy/showBadge; env overrides piiPolicy.
  assert.deepEqual(opts, { piiPolicy: "redact", toolExfilPolicy: "block", showBadge: false });
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
