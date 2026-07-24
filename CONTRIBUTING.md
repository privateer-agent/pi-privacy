# Contributing to pi-privacy

Thanks for helping make privacy on Pi harnesses honest and verifiable. This package
has one non-negotiable principle that every change must uphold — read the next section
before anything else.

## The one rule: verified ≠ asserted

pi-privacy grades a provider by the **strength of its evidence**, never by its marketing.
A green "Verified TEE" badge means remote attestation *actually ran* and the live TLS key
matched the report. A ZDR badge means the provider *promises* not to retain data. Those
must never render, read, or rank alike.

Concretely, a contribution is rejected if it:

- Claims a tier stronger than its evidence — e.g. grading a provider `tee-verified`
  without an attestation path we actively check, or `local` for anything that isn't a
  loopback endpoint (a `.local` mDNS name or `192.168.x` address is a *different machine*,
  and calling it on-device is exactly the overclaim this package exists to prevent).
- **Softens an honest note** in `src/providers/catalog.ts`. Those notes state the *limit*
  of each guarantee ("not TEE-attested", "may log", "policy, not hardware"). They are
  load-bearing. Do not trim them to sound better.
- Presents best-effort detection as a guarantee. The PII/secret detector catches
  *structured patterns* only — never names, addresses, or context — and never sends data
  to a model to detect it. Every user-facing string that reports a detection result must
  keep saying so.

If a change makes a weaker guarantee *look* like a stronger one, it's wrong no matter how
convenient. When in doubt, under-claim.

## Development setup

```bash
nvm use            # Node 22.19.0 (the Pi runtime floor; see .nvmrc / engines)
npm ci             # install exactly the locked tree
npm run typecheck  # tsc --noEmit
npm test           # unit tests (node --test over tests/*.test.ts)
```

Offline integration smokes — load the extension + published package entry through Pi's
real resource loader:

```bash
npm run smoke:extension
npm run smoke:package
```

Live smokes hit real infrastructure and need network + keys, so they are **not** part of
CI. Run them yourself when touching attestation or ZDR:

```bash
npm run smoke:attest   # verifies REAL tinfoil / NEAR enclaves
npm run smoke:zdr      # proves OpenRouter ZDR routing is enforced (needs OPENROUTER_API_KEY)
```

CI (typecheck + tests + offline smokes, on Node 22.19.0 and current) must be green before
a PR merges.

## Adding a provider

This is the most common community contribution, and the honest ladder makes it
mechanical. Edit `src/providers/catalog.ts`:

1. Add an entry to `PRIVACY_PROVIDERS` with the **honest** tier it can offer:
   - `tee-verified` — **only** if you also add an attestation path we actively verify
     (see `src/posture/verify.ts`). A provider that merely *claims* a TEE is
     `tee-unverified`, resolved at runtime — never a static `tee-verified`.
   - `zdr-policy` — the provider promises zero retention but it's unverifiable.
   - `zdr-enforced` — only via a `postureAware` provider whose enforcement we can observe
     (like OpenRouter's 404-when-unsatisfiable).
   - `local` — reserved for the runtime loopback check; don't set it statically except
     for a provider that is loopback by definition (e.g. `ollama`).
   - `standard` — no verifiable channel. Providers with no privacy story stay here with
     **no badge**; that's correct, not a gap.
2. Write the `note` so it states where to get a key **and the limit of the guarantee**.
   Copy the tone of the existing notes.
3. If it's a config-only provider Pi doesn't ship, add a seed model to `SEED_MODELS` in
   `src/extension.ts` so it appears without a live model listing.
4. Add a test in `tests/` (see `posture.test.ts` / `extension.test.ts`).

Prefer opening a **Provider request** issue first if you're unsure how to grade it — we'll
work out the honest tier together.

## Adding a detection pattern

Secrets and structured PII live in `src/pii/detect.ts`. New patterns should be
**prefix-anchored or checksum-validated** (Luhn, IBAN mod-97) to keep precision high — we
deliberately avoid entropy heuristics that flag every hash or id. Add the type to
`PiiType`, a `PATTERNS` entry (with a `validate` fn if it can false-positive), the
`PLACEHOLDER`/`summarizePii` labels, and — if it's a credential — `SECRET_TYPES`. Cover it
in `tests/pii.test.ts`, including a near-miss that must **not** match.

## Pull requests

- One focused change per PR; keep the honest notes and labels intact.
- `npm run typecheck && npm test` green locally; add tests for new behavior.
- Update `README.md` and add a `CHANGELOG.md` entry under `[Unreleased]`.
- Match the surrounding code's style and comment density — this codebase documents *why*,
  not *what*.

## Reporting security issues

Please do **not** open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).

## License

By contributing you agree your contributions are licensed under the project's
[MIT license](LICENSE).
