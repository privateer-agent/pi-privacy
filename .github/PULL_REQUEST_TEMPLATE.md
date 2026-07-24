<!-- Thanks for contributing! Keep the honesty discipline intact — see CONTRIBUTING.md. -->

## What & why

<!-- What does this change, and what problem does it solve? -->

## The honesty check (required)

Confirm your change keeps *verified ≠ asserted* intact:

- [ ] No tier is graded stronger than its evidence (no static `tee-verified` without an
      attestation path; no `local` for anything but a loopback endpoint).
- [ ] Honest catalog notes / user-facing labels are **not** softened.
- [ ] Any best-effort detection is still reported as best-effort, never as a guarantee.
- [ ] N/A — this change doesn't touch grading, badges, notes, or detection.

## Checklist

- [ ] `npm run typecheck` and `npm test` pass locally
- [ ] Added/updated tests for the behavior
- [ ] Updated `README.md` (if user-facing) and added a `CHANGELOG.md` entry under `[Unreleased]`
- [ ] Ran the relevant smoke(s) if touching attestation/ZDR (`npm run smoke:attest` / `smoke:zdr`)
