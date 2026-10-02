# CLAUDE.md

Guidance for Claude Code when working in this repository.

## What this is

`@gainratio/privacy-core` is a browser-side structured-identifier redaction boundary for LLM calls: raw
text stays on-device, only policy-approved redacted text egresses, and replies
are rehydrated locally from an in-memory vault. The current version and what has
shipped live in `CHANGELOG.md` and on npm — don't restate release status in this
file.

## Stack

TypeScript strict / pnpm (pinned via `packageManager`) / Node >= 22.13 (24 in CI) /
Biome (lint + format + cognitive-complexity) / Vitest 4 with coverage thresholds
pinned at 100% (statements / lines / functions / branches) / Playwright e2e /
`tsc` build. One runtime dependency — `@edgeproc/avow`, the receipt-signing
envelope; everything else in `devDependencies` is toolchain.

## Layout

```
src/            library source — see docs/ARCHITECTURE.md for the 1:1 module map
  index.ts      public API barrel (production surface, nothing else)
  egress.ts     the enforcement layer: branded RedactedPayload + LlmProvider + unsafeBypass
  detect/       deterministic detection spine (patterns + checksums + dictionaries)
  providers/    NoLLMProvider (offline echo), OpenRouterProvider, makeProvider
  testing.ts    fixtures — exported ONLY via the ./testing subpath
test/           Vitest unit tests
e2e/            Playwright wire-proof (only placeholders cross the wire)
examples/demo/  runnable Vite demo consuming only the public API
docs/           ARCHITECTURE.md, QUICKSTART.md (diagrams are inline mermaid — no build step)
```

## Invariants (don't break without updating the docs)

- **The type-enforced Egress Guard is the enforcement layer.** Providers accept only the branded
  `RedactedPayload`; `redactForEgress` is its only public constructor. Handing raw
  text to a provider is a *compile error*. `mintPendingRedaction` never leaves the
  internal module; fixtures never leave `./testing`.
- **Redaction is reversible.** Same value → same typed placeholder (`[CARD_1]`);
  `rehydrate` restores real values locally, after the reply, on-device.
- **The vault is in-memory (v0), by design.** It clears on reload; nothing sensitive
  persists. The encrypted IndexedDB vault is a labeled roadmap item — don't imply it
  exists.
- **Detection stays deterministic** (regex + checksums + dictionaries). The
  contextual NER tier is deferred and arrives only as a bounded, off-by-default
  adapter.
- **`unsafeBypass` always emits an `AuditEntry`.** The escape hatch exists to be
  visible; a silent bypass is a security bug (see SECURITY.md).

## Workflow

- TDD: red → green → refactor; bug fixes start with a failing regression test.
- Branch off `main` → PR → CI green → merge → delete branch.
- Docs follow code: README/ARCHITECTURE describe only what is shipped — no claims
  about unshipped runtime behaviour.

## Commands

```bash
pnpm install         # setup (Node >= 22.13)
pnpm gate            # THE gate: lint → typecheck → test (cov) → e2e → build
pnpm demo            # run the wow-loop demo at localhost:5173
pnpm test            # vitest run --coverage (thresholds enforced)
pnpm test:e2e        # Playwright wire-proof (needs: pnpm exec playwright install --with-deps chromium)
pnpm lint:fix        # biome check --write
```

## Quality Gates (Non-Negotiable)

Each rule carries the failure it exists to prevent:

- **`pnpm gate` green before every push, and CI literally runs `pnpm gate`.**
  If the local gate and the CI gate ever describe different steps, a change can
  pass locally and break remotely (or vice versa). Drift between them is a config
  bug, fixed in the same commit that finds it — never worked around.
- **Coverage thresholds are enforced, not reported.** They sit at 100% because a
  floor below the achieved number silently absorbs a regression. This repo once
  sat at 79% branch coverage behind a fully green suite — the OpenRouter error
  path, the unknown-token rehydrate fallback, and the overlap tie-break had zero
  tests until thresholds forced them into the light.
- **The e2e wire-proof must keep driving the real demo.** A green unit suite is
  not proof the product works: a feature can be unit-green yet unreachable in the
  app. Only the placeholders-on-the-wire Playwright assertion proves the actual
  promise — that no raw value crosses the network boundary.
- **Never mix browser-safe and node-only exports in a barrel.** A single
  `node:fs` re-export in a shared barrel poisons every browser importer:
  build-green, runtime-dead, and only e2e catches it. `src/index.ts` stays
  browser-safe.
- **Scheduled workflows count as CI.** The weekly `dagger.yml` run can catch a
  live CVE behind an otherwise green badge. Check
  `gh run list --workflow=dagger.yml` — a red scheduled run is a red repo.

## WASM / edge-compute readiness

privacy-core ships no browser WASM runtime today — the detection spine is pure
TypeScript. The WASM/edge-compute hardening rules (vendored WASM runtimes with
parity-tested TS, and sqlite-wasm/OPFS storage) become applicable only when
in-browser NER models land (the deferred contextual-NER roadmap item). Adopt a
proven ORT-web embedder hardening config at that point.
