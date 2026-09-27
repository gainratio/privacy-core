# Contributing

Thanks for your interest. This is a small, deliberately-scoped library — the bar for
new surface area is high, but fixes, tests, and detection-rule improvements are very
welcome.

## Local setup

```bash
pnpm install
```

Node >= 22.13 and pnpm (version pinned via `packageManager` in `package.json`).

## Quality gate (run before opening a PR)

```bash
pnpm gate
```

That one command is the whole bar: Biome lint/format → `tsc` typecheck (library +
demo) → Vitest with coverage thresholds → Playwright e2e → build. The CI workflow
(`.github/workflows/dagger.yml`, via Dagger) runs the same command — if it passes locally, it
passes remotely.

## Test layout

- `test/` — Vitest unit tests (detection rules, vault, egress guard, providers,
  redact→rehydrate roundtrip).
- `e2e/` — Playwright headless-chromium proof: drives the real demo, intercepts the
  outbound request, and asserts **only placeholders cross the wire**.

New behavior lands with its test in the same commit. Bug fixes start with a failing
regression test.

## Invariants (don't break these)

- **The Egress Guard is load-bearing.** `redactForEgress` stays the only public
  constructor of `RedactedPayload`; providers accept only the brand. Never export
  `mintPendingRedaction` from the main barrel.
- **Test fixtures live behind `./testing`** — never in the production barrel
  (`src/index.ts`), so a fixture can't ship by accident.
- **`unsafeBypass` always audits.** The escape hatch exists to be visible.
- **Detection stays deterministic** — regex + checksums + dictionaries. Inference
  tiers (NER) arrive only as bounded, off-by-default adapters.
