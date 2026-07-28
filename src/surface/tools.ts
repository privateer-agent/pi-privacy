// The tool-surface axis — WHO ELSE IS IN THE ROOM.
//
// Every other gate in this package is reactive: it judges one request, one tool
// call, one model switch. None of them answer the question you'd want answered
// BEFORE any of that — given that my model channel is a verified enclave, what
// other parties are in this session, and who supplied them?
//
// That question has teeth in Pi specifically. Pi has no MCP (by design); its
// third-party surface is skills and extensions, and it loads both from `.pi/` and
// `.agents/` under the CWD — which means THEY ARRIVE WITH THE REPOSITORY YOU
// CLONED. Pi's own docs say so plainly: "Skills can instruct the model to perform
// any action and may include executable code the model invokes." pi-privacy already
// made this exact argument for configuration (a project you open can't disarm your
// guards); a project can still SUPPLY A CAPABILITY, and nothing was watching that.
//
// This module is the pure, unit-testable half: classify one tool by PROVENANCE (who
// supplied it — a fact Pi hands us in sourceInfo) and by REACH (what its schema
// declares it can touch — a heuristic over text its author wrote).
//
// ── the honesty rule, same as everywhere ────────────────────────────────────────
// Two things must never render alike:
//   * DECLARED reach — "this tool's parameters carry a URL surface". Evidence: none.
//     It is the tool author's own description, and an author who wanted to hide it
//     simply wouldn't mention it.
//   * OBSERVED egress — "we saw this call go to this host". Evidence: observable.
//     That lives in ledger.ts and is the only place a host may be named as fact.
// Reach is therefore always labeled as a capability, never as behaviour, exactly as
// the picker says "Verifiable TEE" and never the live "Verified".
//
// And the subtler one: PROVENANCE IS NOT SAFETY. "builtin" does not mean safe, it
// means "not supplied by your repo". A project-supplied tool is usually just the
// repo's legitimate tooling. The wording says "you didn't supply this", never "this
// is malicious".

import { LOCAL_TOOLS } from "../ext/toolgate.ts";

// Where a tool came from. Ordered loosely by how much of your own choice it
// represents — `builtin` you got by running pi, `project` you got by cloning.
export type ToolProvenance =
  | "builtin" // pi's own tools
  | "user" // ~/.pi/agent/… — you installed it, for every project
  | "package" // a pi package you installed (sourceInfo.origin === "package")
  | "project" // .pi/ or .agents/ under cwd — ARRIVED WITH THE REPOSITORY
  | "temporary" // --skill / CLI override, this run only
  | "unknown"; // no source metadata — unattributed, not "fine"

// What a tool DECLARES it can touch. A capability claim, never an observation.
export type ToolReach =
  | "local" // a pi builtin known to touch only the local filesystem
  | "shell" // bash — unbounded by construction, no schema can narrow it
  | "network" // declared: parameters or description carry a URL surface
  | "unknown"; // nothing to go on — UNASSESSED, which is not the same as safe

// The structural subset of Pi's ToolInfo we need. Kept structural (like PiModel in
// extension.ts) so this compiles without depending on Pi's exact internal types, and
// so a host can feed it anything shaped right.
export interface ToolInfoLike {
  name?: string;
  description?: string;
  parameters?: unknown;
  promptGuidelines?: string;
  sourceInfo?: {
    path?: string;
    source?: string;
    scope?: string; // "user" | "project" | "temporary"
    origin?: string; // "package" | "top-level"
    baseDir?: string;
  };
}

export interface ToolSurfaceEntry {
  name: string;
  provenance: ToolProvenance;
  // CAPABILITY, from the tool's own schema/description. Never an observation.
  reach: ToolReach;
  // Where it came from, so the user can go read it. The single most useful thing we
  // can offer about a tool we refuse to characterize further.
  sourcePath?: string;
  glyph: string;
  provenanceLabel: string;
  reachLabel: string;
  // One honest line, present only when the entry deserves attention. Absence means
  // "nothing to flag", NOT "audited and safe".
  concern?: string;
}

// Pi's own coding tools (core/tools/index.ts: createCodingTools). Used only as a
// fallback when source metadata doesn't identify the tool — see toolProvenance for
// why the name alone is never allowed to WIN against sourceInfo.
const BUILTIN_TOOLS: ReadonlySet<string> = new Set([
  "bash",
  "read",
  "write",
  "edit",
  "grep",
  "find",
  "ls",
]);

// Tools whose reach is unbounded by construction. A schema can narrow what a
// parameter looks like; it cannot narrow what a shell command can do.
const SHELL_TOOLS: ReadonlySet<string> = new Set(["bash"]);

// Parameter names that are a network surface. Deliberately a small, high-precision
// list of names that MEAN an address — not a fuzzy scan for words like "fetch" or
// "api", which would flag half of every tool schema and train people to ignore the
// column. Missing a cleverly-named parameter is the acceptable failure here: the
// ledger catches what actually egresses, and this column only ever claims "declared".
const URL_PARAM = /^(?:url|uri|endpoint|host|hostname|origin|webhook|server|base_?url|address)$/i;

// A literal http(s) URL in prose the tool author wrote.
const URL_IN_TEXT = /\bhttps?:\/\//i;

// Walk a JSON-Schema-ish parameters object for property names that are a network
// surface. Depth-capped: a schema is attacker-adjacent input (it can come from a
// project-supplied extension), so this must terminate on anything, including a cycle.
function schemaNamesNetwork(schema: unknown, depth = 0, seen = new Set<object>()): boolean {
  if (depth > 6 || schema === null || typeof schema !== "object") return false;
  if (seen.has(schema)) return false; // a $defs-style back-reference, already answered
  seen.add(schema);
  if (Array.isArray(schema)) return schema.some((s) => schemaNamesNetwork(s, depth + 1, seen));
  const obj = schema as Record<string, unknown>;

  const props = obj.properties;
  if (props && typeof props === "object" && !Array.isArray(props)) {
    for (const [key, val] of Object.entries(props as Record<string, unknown>)) {
      if (URL_PARAM.test(key)) return true;
      // Recurse into the property's own schema — a nested `{ config: { url } }` is
      // still a network surface, and only checking top-level names would miss it.
      if (schemaNamesNetwork(val, depth + 1, seen)) return true;
    }
  }
  // The other containers a schema nests through. Deliberately NOT every key: walking
  // arbitrary values would let a `description` string decide the result.
  for (const key of ["items", "additionalProperties", "oneOf", "anyOf", "allOf", "$defs"]) {
    if (key in obj && schemaNamesNetwork(obj[key], depth + 1, seen)) return true;
  }
  return false;
}

// Who supplied this tool. sourceInfo is a FACT Pi hands us (core/source-info.ts), so
// it is consulted first and the built-in name list is only a fallback.
//
// The ordering matters and is a security property, not a style choice: Pi lets an
// extension "replace built-in tools entirely", so a project-supplied extension can
// register a tool called `bash` or `read`. Checking the name first would let it
// launder itself into the `builtin` bucket — the one bucket that never gets flagged.
// A project/temporary scope therefore always wins over a familiar name.
export function toolProvenance(info: ToolInfoLike): ToolProvenance {
  const si = info.sourceInfo;
  if (si?.scope === "project") return "project";
  if (si?.scope === "temporary") return "temporary";
  if (info.name && BUILTIN_TOOLS.has(info.name)) return "builtin";
  if (si?.origin === "package") return "package";
  if (si?.scope === "user") return "user";
  return "unknown";
}

// What the tool DECLARES it can reach. Pure capability; see the header.
export function toolReach(info: ToolInfoLike, provenance: ToolProvenance): ToolReach {
  const name = info.name ?? "";
  if (SHELL_TOOLS.has(name) && provenance === "builtin") return "shell";
  // `local` is asserted ONLY for a genuine pi builtin. The same name coming from
  // somewhere else is a different tool that merely borrowed the name — calling a
  // project-supplied `read` "local files only" would be precisely the overclaim this
  // package exists to prevent.
  if (LOCAL_TOOLS.has(name) && provenance === "builtin") return "local";
  if (SHELL_TOOLS.has(name)) return "shell"; // a non-builtin `bash` is still a shell
  if (schemaNamesNetwork(info.parameters)) return "network";
  if (URL_IN_TEXT.test(info.description ?? "") || URL_IN_TEXT.test(info.promptGuidelines ?? "")) return "network";
  return "unknown";
}

const PROVENANCE_LABEL: Record<ToolProvenance, string> = {
  builtin: "builtin",
  user: "user",
  package: "package",
  project: "project",
  temporary: "temporary",
  unknown: "unattributed",
};

// Reach wording. Every non-trivial value carries its evidence grade in the text —
// "(declared)" for a capability claim, "unassessed" for the absence of one. There is
// deliberately no word here that could be read as "we checked and it's fine".
const REACH_LABEL: Record<ToolReach, string> = {
  local: "local files only",
  shell: "shell (unbounded)",
  network: "network (declared)",
  unknown: "unassessed",
};

// Provenance you did not choose: it came with the working directory or a CLI flag
// for this run. The only bucket phase 1 flags.
export function isRepoSupplied(p: ToolProvenance): boolean {
  return p === "project" || p === "temporary";
}

export function classifyTool(info: ToolInfoLike): ToolSurfaceEntry {
  const provenance = toolProvenance(info);
  const reach = toolReach(info, provenance);
  const name = info.name ?? "(unnamed)";
  const flagged = isRepoSupplied(provenance) || provenance === "unknown";
  return {
    name,
    provenance,
    reach,
    sourcePath: info.sourceInfo?.path,
    glyph: flagged ? "⚠" : "•",
    provenanceLabel: PROVENANCE_LABEL[provenance],
    reachLabel: REACH_LABEL[reach],
    concern: concernFor(provenance, info.sourceInfo?.path),
  };
}

function concernFor(p: ToolProvenance, path?: string): string | undefined {
  const where = path ? ` (${path})` : "";
  switch (p) {
    case "project":
      return `supplied by this project${where}, not by you — it arrived with the repository`;
    case "temporary":
      return `supplied by a CLI override for this run${where}, not by your configuration`;
    case "unknown":
      return "no source metadata — pi-privacy can't say where this came from";
    default:
      return undefined;
  }
}

// Sort order: the entries that deserve attention first, then stable alphabetical so
// the listing is deterministic across runs (no Date, no random).
const PROVENANCE_ORDER: ToolProvenance[] = ["project", "temporary", "unknown", "package", "user", "builtin"];

export function rankSurface(tools: ToolInfoLike[]): ToolSurfaceEntry[] {
  return tools
    .map(classifyTool)
    .sort(
      (a, b) =>
        PROVENANCE_ORDER.indexOf(a.provenance) - PROVENANCE_ORDER.indexOf(b.provenance) ||
        a.name.localeCompare(b.name),
    );
}

export interface SurfaceSummary {
  total: number;
  // Tools whose provenance is project/temporary/unknown — i.e. everything that is
  // not accounted for by a choice the user made.
  notYours: number;
  byProvenance: Record<ToolProvenance, number>;
}

export function summarizeSurface(entries: ToolSurfaceEntry[]): SurfaceSummary {
  const byProvenance = {
    builtin: 0,
    user: 0,
    package: 0,
    project: 0,
    temporary: 0,
    unknown: 0,
  } as Record<ToolProvenance, number>;
  for (const e of entries) byProvenance[e.provenance]++;
  return {
    total: entries.length,
    notYours: byProvenance.project + byProvenance.temporary + byProvenance.unknown,
    byProvenance,
  };
}

// One display line for an entry, e.g.
// "⚠ project   deploy       .pi/skills/deploy/SKILL.md — shell (unbounded)"
export function surfaceLine(e: ToolSurfaceEntry): string {
  const where = e.sourcePath ? `  ${e.sourcePath}` : "";
  return `${e.glyph} ${e.provenanceLabel.padEnd(9)} ${e.name.padEnd(14)}${where} — ${e.reachLabel}`;
}

// The full `/surface` listing. `collapseBuiltins` folds pi's own tools into a count,
// since 15 lines of "builtin read — local files only" buries the two lines that
// matter. Returns lines (the caller joins) so a host can render them its own way.
export function surfaceReport(entries: ToolSurfaceEntry[], collapseBuiltins = true): string[] {
  const s = summarizeSurface(entries);
  const head =
    `${s.total} tool${s.total === 1 ? "" : "s"} available · ` +
    (s.notYours === 0 ? "all supplied by you or pi" : `${s.notYours} not supplied by you`);
  const shown = collapseBuiltins ? entries.filter((e) => e.provenance !== "builtin") : entries;
  const lines = shown.map(surfaceLine);
  if (collapseBuiltins && s.byProvenance.builtin > 0) lines.push(`  … ${s.byProvenance.builtin} builtin`);
  return [head, ...lines];
}
