# pi-privacy

**Privacy posture + TEE attestation for [Pi](https://pi.dev) providers.** A Pi
extension that cryptographically **verifies** confidential-enclave (TEE) inference,
**enforces** zero-data-retention (ZDR) routing, detects **on-device** inference, and
grades every provider on one honest ladder — so a guarantee you can *prove* never
reads like one a vendor merely *claims*.

## Install

```bash
pi install npm:pi-privacy
```

That's it — Pi loads the extension, which registers the privacy providers below and
starts verifying posture. Check the current model any time with:

```
/verify
```

## The one rule: verified ≠ asserted

Every tier states the strength of its evidence. A green "verified TEE" badge means
remote attestation actually checked the hardware; a ZDR badge means the provider
*promises* not to retain data. Those are different things, and pi-privacy never lets
them look the same.

| Tier | Badge | Evidence | Meaning |
|---|---|---|---|
| `tee-verified` | **Verified TEE** | cryptographic | Remote attestation proved genuine enclave hardware **and** the live TLS key matched the report. |
| `local` | **On-device** | observable | Loopback endpoint — inference runs locally, nothing leaves the machine. |
| `zdr-enforced` | **ZDR (enforced)** | observable | Zero-retention routing actively pinned — requests only reach non-retaining providers. Policy, not hardware. |
| `tee-unverified` | **TEE (unconfirmed)** | none | Provider claims a TEE, but attestation was incomplete or unmatched. |
| `zdr-policy` | **ZDR (by policy)** | policy | Provider promises zero retention; unverifiable. Not hardware, not attested. |
| `standard` | **Standard** | none | No special guarantee. |

## Providers

| Provider | Tier | How it's checked |
|---|---|---|
| `tinfoil` | Verified TEE | SEV-SNP attestation; the enclave's TLS key (SPKI) is pinned against the connection Pi actually uses |
| `nearai` | Verified TEE | Attestation report (Intel TDX + NVIDIA CC) fetched over HTTPS, bound to a fresh nonce |
| `openrouter` | ZDR (posture-aware) | `zdr-policy` until enforcement pins routing → `zdr-enforced` |
| `venice`, `fireworks` | ZDR (by policy) | Provider policy; honest limits noted (e.g. Venice is not TEE-attested) |
| `ollama`, `custom` | On-device | Detected when the endpoint is a loopback URL |

Providers with no verifiable or default privacy channel (Together, DeepSeek, MiniMax,
Qwen, …) are intentionally left `standard` with **no badge** — anything else would
overclaim.

## How verification works

- **Tinfoil (SPKI pinning).** Pi's provider requests flow through a process-wide
  `undici` dispatcher that captures the enclave's TLS public-key fingerprint on the
  *actual inference connection*. That fingerprint is matched against
  `report_data[0:32]` of the signed SEV-SNP attestation — so "verified" means the
  channel you're using demonstrably ends inside the enclave.
- **NEAR (report body).** A fresh nonce is sent with the attestation request; the
  returned report must carry a TEE signing key and hardware evidence and echo the
  nonce (freshness / anti-replay).
- **ZDR (enforced).** For OpenRouter, requests carry
  `provider: { zdr: true, data_collection: "deny" }`. OpenRouter filters routing to
  compliant providers and returns `404 No allowed providers` when the policy can't be
  met — it doesn't silently ignore the constraint, which is why `zdr-enforced` is honest.
- **Local.** A loopback endpoint (`localhost` / `127.0.0.1`) is observable, so on-device
  inference is detected rather than claimed.

These are *pragmatic* checks suited to an interactive agent, not a replacement for a
full verifier ([nearai/cloud-verifier](https://github.com/nearai/cloud-verifier),
[tinfoilsh/tinfoil-cli](https://github.com/tinfoilsh/tinfoil-cli)); `/verify` prints
the raw report so you can take it to one.

## Programmatic use

```ts
import { makePiPrivacyExtension, verifyModelPosture, effectiveTier } from "pi-privacy";

// Configure the extension (e.g. enforce ZDR, receive posture updates):
const ext = makePiPrivacyExtension({
  enforceOpenRouterZdr: true,          // opt-in; a model with no ZDR endpoint will 404
  onPosture: (r) => renderBadge(r),    // { tier, teePosture?, attestation? }
});

// Verify a specific model on demand:
const posture = await verifyModelPosture("tinfoil", "llama3-3-70b");
// → { tier: "tee-verified", teePosture: "green", attestation: {...} }

// Or just the static/enforcement tier, no network:
effectiveTier("openrouter", { zdrEnforced: true }); // → "zdr-enforced"
```

`makePiPrivacyExtension(options?)` — `installDispatcher`, `registerProviders`,
`enforceOpenRouterZdr`, `useDispatcherTransport`, `onPosture`.

## Requirements

Node ≥ 22.19.0 (the Pi runtime's floor). MIT licensed.
