// Live attestation smoke — verify REAL enclaves, not fixtures.
//
// Run (keys come from the privateer-agent .env):
//   node --env-file=../privateer-agent/.env --import tsx scripts/smoke-attest.ts
//
// Tinfoil is the hard gate: fetch the real well-known document, parse the SEV-SNP
// report, and confirm the live TLS key matches report_data[0:32] → green. Proven
// two ways: the self-contained httpsTransport AND the dispatcher-bound transport
// (the path a Pi extension uses). NEAR is reported informationally (report-body
// attestation; green ideal, yellow acceptable).

import {
  fetchTinfoilAttestation,
  tinfoilTeePosture,
  httpsTransport,
  fetchAttestation,
  teePosture,
} from "../src/attest/attestation.ts";
import { installAttestationDispatcher, dispatcherTransport, getCapturedCert } from "../src/attest/dispatcher.ts";

const NEAR_MODEL = process.env.NEAR_SMOKE_MODEL ?? "zai-org/GLM-5.1-FP8";

async function tinfoil(label: string, transport: typeof httpsTransport) {
  const att = await fetchTinfoilAttestation({}, transport);
  const posture = tinfoilTeePosture(att);
  console.log(`  [tinfoil/${label}] host=${att.host} hw=${att.hardware.join("+") || "none"} matched=${att.tlsKeyMatched} → ${posture.toUpperCase()}`);
  if (att.attestedTlsKeyFp) console.log(`    attested SPKI: ${att.attestedTlsKeyFp}`);
  if (att.liveTlsKeyFp) console.log(`    live SPKI    : ${att.liveTlsKeyFp}`);
  return posture;
}

async function main() {
  console.log("Live attestation smoke\n");

  console.log("── Tinfoil (SEV-SNP SPKI pin) ──");
  const tHttps = await tinfoil("httpsTransport", httpsTransport);

  // Dispatcher path: install, then fetch the doc THROUGH the global dispatcher so
  // the connect hook captures the enclave SPKI, and the transport reads it back.
  installAttestationDispatcher();
  const tDispatch = await tinfoil("dispatcherTransport", dispatcherTransport);
  const cap = getCapturedCert("inference.tinfoil.sh");
  console.log(`    dispatcher captured host cert: ${cap && !cap.error ? "yes" : "no"}`);

  console.log("\n── NEAR AI (report-body) ──");
  let nearPosture = "error";
  try {
    const att = await fetchAttestation({ apiKey: process.env.NEAR_AI_API_KEY }, NEAR_MODEL);
    nearPosture = teePosture(att);
    console.log(`  [nearai] model=${att.model} hw=${att.hardware.join("+") || "none"} signKey=${!!att.signingAddress} nonceEcho=${att.nonceEchoed} → ${nearPosture.toUpperCase()}`);
  } catch (e) {
    console.log(`  [nearai] error: ${(e as Error).message}`);
  }

  console.log("\n════════ ATTESTATION SMOKE VERDICT ════════");
  const tinfoilOk = tHttps === "green" && tDispatch === "green";
  const nearOk = nearPosture === "green" || nearPosture === "yellow";
  console.log(`  Tinfoil verified TEE (both transports green) .. ${tinfoilOk ? "PASS ✅" : "FAIL ❌"}`);
  console.log(`  NEAR attestation reachable (green/yellow) ..... ${nearOk ? "PASS ✅" : "WARN ⚠️  (" + nearPosture + ")"}`);
  console.log(tinfoilOk
    ? "\n  → real enclave SPKI verified end-to-end; the attestation engine is live."
    : "\n  → Tinfoil did not verify green; inspect above.");
  // Hard gate on Tinfoil only (NEAR model id / posture is informational).
  process.exit(tinfoilOk ? 0 : 1);
}

main().catch((e) => {
  console.error("\nATTEST SMOKE ERROR:", e?.stack || e);
  process.exit(2);
});
