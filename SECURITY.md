# Security Policy

## Reporting a vulnerability

Please report security issues **privately**, not in a public issue or PR.

Use GitHub's private vulnerability reporting: on the repository's **Security** tab, click
**Report a vulnerability** ([privateer-agent/pi-privacy security
advisories](https://github.com/privateer-agent/pi-privacy/security/advisories/new)). This
opens a private advisory only the maintainers can see.

Please include: affected version, a description, reproduction steps, and the impact you
see. We aim to acknowledge within a few days and to coordinate a fix and disclosure
timeline with you. We're grateful for responsible disclosure and will credit reporters who
want it.

## Supported versions

pi-privacy is pre-1.0 and ships fixes on the latest published version. Please reproduce on
the current release before reporting.

## Scope — what this package does and does not promise

pi-privacy's guarantees are graded by evidence, and its limits are part of its design.
Understanding them helps target reports at real gaps rather than documented bounds:

- **Attested tiers (`tee-verified`)** rest on the pragmatic checks in
  `src/posture/verify.ts` + `src/attest/` — remote attestation plus a live-TLS-key match.
  These are suited to an interactive agent, **not** a replacement for a full verifier
  (`nearai/cloud-verifier`, `tinfoil-cli`); `/verify` prints the raw report so you can
  independently check it. A flaw that lets an **unattested** channel earn a green verified
  badge is a serious bug — please report it.
- **ZDR tiers** are *policy* (or, for `zdr-enforced`, observably enforced routing), never
  hardware attestation. A provider seeing-but-not-retaining data is within scope of the
  design, not a vulnerability.
- **PII / secret detection is best-effort structured matching**, local and deterministic —
  it never sends data to a model to detect it, and it cannot catch names, addresses, or
  contextual PII. Missed unstructured PII is a known limitation, not a vulnerability. A
  *false-negative on a structured pattern we claim to detect* (e.g. a valid credit-card
  number the Luhn path misses) **is** worth reporting.
- The tool-exfiltration and downgrade gates are best-effort heuristics over a best-effort
  detector. A bypass that defeats the *stated* heuristic (e.g. a loopback URL vouching for
  a sibling egress command in the same line) is in scope; an entirely novel exfil channel
  the heuristic never claimed to cover is a feature request.

When unsure whether something is a bug or a documented limit, report it privately and
we'll sort it out.
