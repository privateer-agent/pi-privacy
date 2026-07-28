import { test } from "node:test";
import assert from "node:assert/strict";
import {
  classifyTool,
  toolProvenance,
  toolReach,
  rankSurface,
  summarizeSurface,
  surfaceReport,
  isRepoSupplied,
  type ToolInfoLike,
} from "../src/surface/tools.ts";

const builtin = (name: string): ToolInfoLike => ({
  name,
  sourceInfo: { scope: "user", source: "builtin", origin: "top-level", path: "<builtin>" },
});
const project = (name: string, extra: Partial<ToolInfoLike> = {}): ToolInfoLike => ({
  name,
  sourceInfo: { scope: "project", origin: "top-level", path: `.pi/extensions/${name}.ts` },
  ...extra,
});

// ── provenance ────────────────────────────────────────────────────────────────

test("provenance: pi's own coding tools are builtin", () => {
  for (const n of ["bash", "read", "write", "edit", "grep", "find", "ls"]) {
    assert.equal(toolProvenance(builtin(n)), "builtin");
  }
});

test("provenance: project scope is project, package origin is package", () => {
  assert.equal(toolProvenance(project("deploy")), "project");
  assert.equal(
    toolProvenance({ name: "grep_web", sourceInfo: { scope: "user", origin: "package", path: "pi-web-tools" } }),
    "package",
  );
  assert.equal(
    toolProvenance({ name: "mytool", sourceInfo: { scope: "user", origin: "top-level", path: "~/.pi/x.ts" } }),
    "user",
  );
  assert.equal(
    toolProvenance({ name: "scratch", sourceInfo: { scope: "temporary", path: "/tmp/s.md" } }),
    "temporary",
  );
});

test("provenance: no source metadata is 'unknown', never quietly 'builtin'", () => {
  assert.equal(toolProvenance({ name: "mystery" }), "unknown");
  const e = classifyTool({ name: "mystery" });
  assert.equal(e.glyph, "⚠");
  assert.match(e.concern ?? "", /can't say where this came from/);
});

// THE security property: pi lets an extension replace built-in tools entirely, so a
// project-supplied tool can register itself as `bash` or `read`. If the familiar name
// won, it would launder straight into the one bucket that never gets flagged.
test("provenance: a project-supplied tool cannot launder itself as a builtin name", () => {
  assert.equal(toolProvenance(project("bash")), "project");
  assert.equal(toolProvenance(project("read")), "project");
  const e = classifyTool(project("read"));
  assert.equal(e.glyph, "⚠");
  assert.match(e.concern ?? "", /arrived with the repository/);
});

test("isRepoSupplied covers exactly what the user did not choose", () => {
  assert.equal(isRepoSupplied("project"), true);
  assert.equal(isRepoSupplied("temporary"), true);
  assert.equal(isRepoSupplied("builtin"), false);
  assert.equal(isRepoSupplied("package"), false);
  assert.equal(isRepoSupplied("user"), false);
});

// ── reach (a CAPABILITY claim, never an observation) ──────────────────────────

test("reach: builtin file tools are local, builtin bash is shell", () => {
  assert.equal(toolReach(builtin("read"), "builtin"), "local");
  assert.equal(toolReach(builtin("edit"), "builtin"), "local");
  assert.equal(toolReach(builtin("bash"), "builtin"), "shell");
});

// The same overclaim in the other direction: a project-supplied `read` is a
// DIFFERENT tool that borrowed the name. Calling it "local files only" would be
// exactly the conflation this package exists to prevent.
test("reach: a non-builtin tool never inherits 'local' from a builtin's name", () => {
  assert.notEqual(toolReach(project("read"), "project"), "local");
  assert.equal(toolReach(project("bash"), "project"), "shell"); // still a shell, though
});

test("reach: a url-ish parameter name is a declared network surface", () => {
  const t = project("fetch_docs", { parameters: { type: "object", properties: { url: { type: "string" } } } });
  assert.equal(toolReach(t, "project"), "network");
  assert.equal(classifyTool(t).reachLabel, "network (declared)");
});

test("reach: nested parameter schemas are walked", () => {
  const t: ToolInfoLike = {
    name: "post",
    parameters: {
      type: "object",
      properties: { config: { type: "object", properties: { endpoint: { type: "string" } } } },
    },
  };
  assert.equal(toolReach(t, "user"), "network");
});

test("reach: a literal URL in the author's own prose counts as declared", () => {
  assert.equal(toolReach({ name: "x", description: "posts to https://api.example.com" }, "user"), "network");
});

test("reach: unrelated parameter names are NOT a network surface", () => {
  const t: ToolInfoLike = {
    name: "summarize",
    description: "Summarize a file for the user",
    parameters: { type: "object", properties: { path: { type: "string" }, api_style: { type: "string" } } },
  };
  assert.equal(toolReach(t, "user"), "unknown");
});

test("reach: a cyclic parameter schema terminates", () => {
  const cyclic: Record<string, unknown> = { type: "object" };
  cyclic.properties = { self: cyclic };
  assert.equal(toolReach({ name: "loop", parameters: cyclic }, "user"), "unknown");
});

// The honesty bound: "unknown" reach must never read as a clean bill of health.
test("reach: an unassessed tool is labeled unassessed, never safe/local/none", () => {
  const e = classifyTool({ name: "mystery", sourceInfo: { scope: "user", origin: "package" } });
  assert.equal(e.reach, "unknown");
  assert.equal(e.reachLabel, "unassessed");
  assert.doesNotMatch(e.reachLabel, /safe|local|no network/i);
});

// ── ranking, summary, report ──────────────────────────────────────────────────

test("rankSurface: attention-worthy first, then stable alphabetical", () => {
  const ranked = rankSurface([
    builtin("read"),
    { name: "zeta", sourceInfo: { scope: "user", origin: "package" } },
    project("deploy"),
    builtin("bash"),
    project("alpha"),
  ]);
  assert.deepEqual(
    ranked.map((e) => e.name),
    ["alpha", "deploy", "zeta", "bash", "read"],
  );
  // Deterministic: the same input always yields the same order.
  assert.deepEqual(
    rankSurface([builtin("read"), project("deploy")]).map((e) => e.name),
    ["deploy", "read"],
  );
});

test("summarizeSurface counts what the user did not supply", () => {
  const s = summarizeSurface(rankSurface([builtin("read"), project("deploy"), { name: "mystery" }]));
  assert.equal(s.total, 3);
  assert.equal(s.notYours, 2); // project + unattributed; the builtin isn't counted
  assert.equal(s.byProvenance.builtin, 1);
  assert.equal(s.byProvenance.project, 1);
  assert.equal(s.byProvenance.unknown, 1);
});

test("surfaceReport: headline names the count, builtins collapse", () => {
  const entries = rankSurface([builtin("read"), builtin("bash"), project("deploy")]);
  const lines = surfaceReport(entries);
  assert.match(lines[0], /3 tools available · 1 not supplied by you/);
  assert.match(lines[1], /deploy/);
  assert.match(lines[at(lines)], /2 builtin/);
  // Nothing repo-supplied → the headline says so without implying an audit.
  const clean = surfaceReport(rankSurface([builtin("read")]));
  assert.match(clean[0], /all supplied by you or pi/);
});

function at(lines: string[]): number {
  return lines.length - 1;
}

test("surfaceReport: a repo-supplied tool's line names where it came from", () => {
  const [, line] = surfaceReport(rankSurface([project("deploy"), builtin("read")]));
  assert.match(line, /^⚠/);
  assert.match(line, /project/);
  assert.match(line, /\.pi\/extensions\/deploy\.ts/); // so the user can go read it
});
