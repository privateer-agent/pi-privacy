// Live proof that OpenRouter ZDR routing is ENFORCED, not silently ignored — the
// honesty gate for badging `zdr-enforced`. Reproduces the two-request check:
//   1. provider.{zdr,data_collection:"deny"} is accepted and routes (200).
//   2. an unsatisfiable policy returns 404 "No allowed providers" — proving the
//      filter is live (OpenRouter refuses to serve rather than ignore it).
//
// Run: node --env-file=../privateer-agent/.env --import tsx scripts/smoke-zdr.ts

import { openRouterZdrPatch } from "../src/ext/patches.ts";

const KEY = process.env.OPENROUTER_API_KEY;
const URL = "https://openrouter.ai/api/v1/chat/completions";

async function post(body: unknown) {
  const res = await fetch(URL, {
    method: "POST",
    headers: { authorization: `Bearer ${KEY}`, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: res.status, json: (await res.json().catch(() => ({}))) as any };
}

async function main() {
  if (!KEY) throw new Error("OPENROUTER_API_KEY not set (use --env-file=../privateer-agent/.env)");
  console.log("OpenRouter ZDR enforcement — live honesty gate\n");

  // 1. Enforced request via the actual patch we ship.
  const enforced = openRouterZdrPatch({
    model: "openai/gpt-4o-mini",
    messages: [{ role: "user", content: "say ok" }],
    max_tokens: 5,
  });
  const a = await post(enforced);
  const served = a.json.provider ?? "(unreported)";
  const routed = a.status === 200 && !!a.json.choices?.[0]?.message;
  console.log(`  [1] zdr+data_collection:deny → status=${a.status} served-by=${served} routed=${routed}`);

  // 2. Unsatisfiable policy → must 404 (proves the filter is enforced).
  const b = await post({
    model: "openai/gpt-4o-mini",
    messages: [{ role: "user", content: "hi" }],
    max_tokens: 5,
    provider: { data_collection: "deny", only: ["novita"] },
  });
  const refused = b.status === 404 || /no allowed providers|data policy/i.test(JSON.stringify(b.json));
  console.log(`  [2] unsatisfiable policy → status=${b.status} refused=${refused}`);
  if (b.json.error?.metadata) console.log(`      ${JSON.stringify(b.json.error.metadata)}`);

  console.log("\n════════ ZDR ENFORCEMENT VERDICT ════════");
  console.log(`  ZDR routing accepted & routes ........... ${routed ? "PASS ✅" : "FAIL ❌"}`);
  console.log(`  enforcement is live (refuses when unmet)  ${refused ? "PASS ✅" : "FAIL ❌"}`);
  const pass = routed && refused;
  console.log(pass
    ? "\n  → zdr-enforced is an honest badge: routing is observably constrained to\n    zero-retention providers (enforcement of a policy, not attestation)."
    : "\n  → could not confirm enforcement; keep OpenRouter at zdr-policy.");
  process.exit(pass ? 0 : 1);
}

main().catch((e) => {
  console.error("\nZDR SMOKE ERROR:", e?.stack || e);
  process.exit(2);
});
