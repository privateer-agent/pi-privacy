# Changelog

All notable changes to **pi-privacy** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.4.0]: https://github.com/privateer-agent/pi-privacy/releases/tag/v0.4.0
[0.3.0]: https://github.com/privateer-agent/pi-privacy/compare/v0.2.1...ca27cb6
[0.2.1]: https://github.com/privateer-agent/pi-privacy/releases/tag/v0.2.1
[0.2.0]: https://github.com/privateer-agent/pi-privacy/releases/tag/v0.2.0
[0.1.1]: https://github.com/privateer-agent/pi-privacy/releases/tag/v0.1.1
[0.1.0]: https://github.com/privateer-agent/pi-privacy/releases/tag/v0.1.0
