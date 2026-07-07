// Live extension smoke — load makePiPrivacyExtension through Pi's REAL resource
// loader and confirm it registers the config-only providers end-to-end (the
// pending-registration → model-registry pipeline), with no error diagnostics.
// No network / no turn: this isolates "does the extension wire into Pi correctly".
//
// Run: node --import tsx scripts/smoke-extension.ts

import { createAgentSessionServices } from "@earendil-works/pi-coding-agent";
import { mkdirSync } from "node:fs";
import { makePiPrivacyExtension } from "../src/extension.ts";

const AGENT_DIR = "/private/tmp/claude-501/pv-piprivacy-agent";
const CWD = "/private/tmp/claude-501/pv-piprivacy-work";
mkdirSync(AGENT_DIR, { recursive: true });
mkdirSync(CWD, { recursive: true });

async function main() {
  const ext = makePiPrivacyExtension({ installDispatcher: true });

  const services = await createAgentSessionServices({
    cwd: CWD,
    agentDir: AGENT_DIR,
    resourceLoaderOptions: { extensionFactories: [ext] },
  });

  const errors = services.diagnostics.filter((d) => d.type === "error");
  const reg: any = services.modelRegistry;
  const found = {
    tinfoil: !!reg.find("tinfoil", "deepseek-v4-pro"),
    nearai: !!reg.find("nearai", "zai-org/GLM-5.1-FP8"),
    venice: !!reg.find("venice", "qwen3-coder-480b-a35b-instruct-turbo"),
    ollama: !!reg.find("ollama", "llama3.1"),
  };

  console.log("Live extension load — via Pi createAgentSessionServices\n");
  for (const [id, ok] of Object.entries(found)) console.log(`  registered ${id.padEnd(8)} ${ok ? "✅" : "❌"}`);
  console.log(`  error diagnostics: ${errors.length}`);
  for (const e of errors) console.log(`    - ${e.message}`);

  const allRegistered = Object.values(found).every(Boolean);
  const clean = errors.length === 0;
  console.log("\n════════ EXTENSION LOAD VERDICT ════════");
  console.log(`  all config-only providers registered ... ${allRegistered ? "PASS ✅" : "FAIL ❌"}`);
  console.log(`  no error diagnostics ................... ${clean ? "PASS ✅" : "FAIL ❌"}`);
  console.log(allRegistered && clean
    ? "\n  → the extension wires into a real Pi session; providers resolve. "
    : "\n  → inspect diagnostics above.");
  process.exit(allRegistered && clean ? 0 : 1);
}

main().catch((e) => {
  console.error("\nEXT LOAD SMOKE ERROR:", e?.stack || e);
  process.exit(2);
});
