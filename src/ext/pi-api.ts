// The structural subset of Pi's extension surface that this package uses.
//
// Deliberately STRUCTURAL rather than an import of Pi's own types: pi-privacy
// declares @earendil-works/pi-coding-agent as an OPTIONAL peer, so it must compile
// and run without it. Every method here is feature-detected at the call site — a
// restricted context (the command context, a print/JSON run) legitimately omits
// most of them. Verified against the installed ExtensionAPI / ProviderConfigInput
// in 0.80.3.

import type { ToolInfoLike } from "../surface/tools.ts";

export interface PiModel {
  provider?: string;
  id?: string;
  name?: string;
  baseUrl?: string;
}

// The model registry Pi exposes on event/command contexts. getAvailable() is the
// models the user has auth for (the honest set to offer in a picker); getAll() is
// every configured model. Both feature-detected — a restricted context may omit them.
export interface PiModelRegistry {
  getAvailable?(): PiModel[];
  getAll?(): PiModel[];
}

export interface PiUi {
  notify?: (message: string, level?: string) => void;
  select?: (title: string, options: string[], opts?: unknown) => Promise<string | undefined>;
  // Badge render surfaces, in descending preference. Present on event contexts (not
  // the restricted command context), and each host UI/mode may expose a different
  // subset — so every one is feature-detected before use and the badge walks a
  // fallback chain (see badgeSinks) rather than depending on any single method.
  setStatus?: (key: string, text: string | undefined) => void;
  setWidget?: (key: string, content: string[] | undefined, options?: unknown) => void;
  setTitle?: (title: string) => void;
}

export interface PiCtx {
  hasUI?: boolean;
  modelRegistry?: PiModelRegistry;
  getModel?(): PiModel | undefined;
  // Every configured tool with its source metadata — the input to the tool-surface
  // axis. Present on event contexts; the restricted COMMAND context may omit it,
  // which is why the extension keeps a snapshot taken at session_start.
  getAllTools?(): ToolInfoLike[];
  ui?: PiUi;
}

export interface PiExtensionApiLike {
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
