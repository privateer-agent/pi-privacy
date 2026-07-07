# pi-privacy *(working name — final TBD at publish)*

Privacy posture + TEE attestation for [Pi](https://pi.dev) providers, as an
installable extension. It registers privacy-oriented providers, **cryptographically
verifies** confidential-enclave (TEE) inference, **enforces or honestly labels**
zero-data-retention (ZDR), and detects **on-device** (local) inference — all graded
on one honest ladder.

Extracted from [privateer-agent](../privateer-agent)'s attestation moat so any Pi
user can install it; privateer-agent depends on this package.

## The one rule: verified ≠ asserted

The whole point is to **never conflate a guarantee we *verified* with one a provider
*claims*.** Each tier is explicit about the strength of its evidence:

| Tier | Label | Evidence | What it means |
|---|---|---|---|
| `tee-verified` | **Verified TEE** | cryptographic | Remote attestation proved genuine enclave hardware **and** the live TLS key matched the report. |
| `local` | **On-device** | observable | Loopback endpoint — inference is local, nothing leaves the machine. |
| `zdr-enforced` | **ZDR (enforced)** | observable | Zero-retention routing actively pinned this session. Policy, not hardware — **not attested**. |
| `tee-unverified` | **TEE (unconfirmed)** | none | Provider claims a TEE, but attestation was incomplete / unmatched here. |
| `zdr-policy` | **ZDR (by policy)** | policy | Provider *promises* zero retention; unverifiable. Not hardware, not attested. |
| `standard` | **Standard** | none | No special guarantee. |

A ZDR badge must never read as "verified." That's not politeness — it's the
difference between a proof and a promise, and it's what makes the green badges
worth trusting.

## Providers

- **Verified TEE (attested):** `tinfoil` (SPKI pinned via an out-of-band dispatcher),
  `nearai` (attestation in the report body over HTTPS).
- **ZDR:** `openrouter` (posture-aware: `zdr-policy` until routing is enforced →
  `zdr-enforced`), `venice` and `fireworks` (`zdr-policy` — honest policy notes preserved).
- **Local:** `ollama`, and any `custom` OpenAI-compatible endpoint on a loopback URL.

Providers with no verifiable or default privacy channel (Together, DeepSeek, MiniMax,
Qwen, …) are intentionally left `standard` with **no badge** — claiming otherwise
would overclaim.

## Status

Taxonomy + attestation engine, **verified against real enclaves**:

- `src/posture/tiers.ts`, `src/providers/catalog.ts`, `effectiveTier` — the honest ladder.
- `src/attest/attestation.ts` — TEE attestation (NEAR report-body, Tinfoil SEV-SNP
  SPKI pin), ported from privateer 0.2 minus the private server-proxy path.
- `src/attest/dispatcher.ts` — the out-of-band undici dispatcher + a `dispatcherTransport`
  that binds attestation to the real provider connection.
- 17 unit tests; `scripts/smoke-attest.ts` verifies live: **Tinfoil green** (attested
  SPKI == live SPKI, via both the self-contained and dispatcher transports) and
  **NEAR green** (NVIDIA + Intel TDX, signing key, nonce echoed).

- `src/extension.ts` — the installable Pi extension (`makePiPrivacyExtension` +
  default export): installs the dispatcher at extension-init, registers the
  config-only providers (tinfoil/nearai/venice/ollama — built-ins left to Pi),
  patches venice / OpenRouter requests, tracks the current model to compute posture,
  and adds `/verify`. Verified live via `scripts/smoke-extension.ts`: loads through
  Pi's real resource loader and all four providers resolve, zero diagnostics.

## Install (marketplace)

```jsonc
// pi settings — load the default extension
{ "extensions": ["pi-privacy"] }
```

Or embed it: `makePiPrivacyExtension({ onPosture })` in your `extensionFactories`.

- ZDR enforcement **verified live** (`scripts/smoke-zdr.ts`): OpenRouter honors
  `provider.{zdr,data_collection:"deny"}` and 404s when the policy can't be met —
  so `zdr-enforced` is an honest badge (enforcement of a policy, observable; not attestation).

privateer-agent consumes this package (`file:../pi-privacy`) and its
`scripts/smoke-integration.ts` verifies a real Tinfoil turn's connection against the
enclave attestation end-to-end.

Requires Node ≥ 22.19.0 (the Pi stack's floor). MIT.
