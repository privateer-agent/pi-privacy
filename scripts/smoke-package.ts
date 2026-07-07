// Verify the PUBLISHED package entry loads the way Pi loads an installed package:
// via file-based extension discovery (the extensions/ entry's default export),
// not the programmatic extensionFactories path. Proves the pi-package manifest +
// entry file work end-to-end before publishing.
//
// Run: node --import tsx scripts/smoke-package.ts

import { createAgentSessionServices } from "@earendil-works/pi-coding-agent";
import { mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const ENTRY = resolve(HERE, "..", "extensions", "pi-privacy.ts");
const AGENT_DIR = "/private/tmp/claude-501/pv-pkg-agent";
const CWD = "/private/tmp/claude-501/pv-pkg-work";
mkdirSync(AGENT_DIR, { recursive: true });
mkdirSync(CWD, { recursive: true });

async function main() {
  console.log("Package load — via Pi file-based extension discovery\n");
  console.log(`  entry: ${ENTRY}`);

  const services = await createAgentSessionServices({
    cwd: CWD,
    agentDir: AGENT_DIR,
    resourceLoaderOptions: { additionalExtensionPaths: [ENTRY] },
  });

  const errors = services.diagnostics.filter((d) => d.type === "error");
  const reg: any = services.modelRegistry;
  const found = ["tinfoil", "nearai", "venice", "ollama"].map((id) => {
    const seed: Record<string, string> = {
      tinfoil: "deepseek-v4-pro",
      nearai: "zai-org/GLM-5.1-FP8",
      venice: "qwen3-coder-480b-a35b-instruct-turbo",
      ollama: "llama3.1",
    };
    return { id, ok: !!reg.find(id, seed[id]) };
  });

  for (const f of found) console.log(`  ${f.id.padEnd(8)} ${f.ok ? "✅" : "❌"}`);
  console.log(`  error diagnostics: ${errors.length}`);
  for (const e of errors) console.log(`    - ${e.message}`);

  const pass = found.every((f) => f.ok) && errors.length === 0;
  console.log("\n════════ PACKAGE ENTRY VERDICT ════════");
  console.log(`  extensions/ entry loads + registers providers ... ${pass ? "PASS ✅" : "FAIL ❌"}`);
  console.log(pass
    ? "\n  → the pi-package format loads exactly as an installed package would."
    : "\n  → inspect diagnostics above.");
  process.exit(pass ? 0 : 1);
}

main().catch((e) => {
  console.error("\nPACKAGE SMOKE ERROR:", e?.stack || e);
  process.exit(2);
});
