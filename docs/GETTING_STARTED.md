# Getting started for developers

This takes you from nothing to a green local build and your first change. Every
command below was run from a fresh clone on macOS on 25 Sep 2026; the times are what
it took there, with a warm pnpm cache. Back to the [README](../README.md).

## 1. What you need

| Tool | Version | How to get it |
| --- | --- | --- |
| Node.js | 24.x (CI uses 24.16.0; `package.json` allows 22.13+) | [nodejs.org](https://nodejs.org), or `nvm install 24` |
| pnpm | 11.5.0, pinned in `package.json` | `corepack enable` (ships with Node) |
| Chromium for Playwright | whatever `@playwright/test` asks for | `pnpm exec playwright install chromium` (step 2) |
| Git and the `gh` CLI | any recent | for cloning and opening PRs |

You do not need Docker or Dagger for local work. CI runs the same check inside Dagger.

Traps we actually hit:

- **Node 26 breaks the corepack pnpm shim.** Running `pnpm` under Node 26.5 fails with
  `ERR_VM_DYNAMIC_IMPORT_CALLBACK_MISSING`. Switch to Node 24 (`nvm use 24`) and run
  `corepack enable` again.
- **Something else on port 5173 breaks the browser tests.** The Playwright tests
  reuse any server already on port 5173. If it is not this demo (another project's dev
  server, or a `pnpm demo` you left running), both browser tests fail with
  "the server on :5173 is not the privacy-core demo". Check with `lsof -ti tcp:5173`
  and stop it.
- **Biome also checks formatting.** `pnpm gate` fails on a badly formatted file. Run
  `pnpm lint:fix` before you commit.

## 2. Clone, install, run

```bash
git clone https://github.com/hseshadr/privacy-core   # 1s
cd privacy-core
corepack enable                                      # 0s
pnpm install                                         # 1s (warm cache; allow a minute cold)
pnpm exec playwright install chromium                # 3s if cached; about a minute the first time
pnpm test                                            # 14s
```

Success for `pnpm test` looks like this at the end:

```text
 Test Files  28 passed (28)
      Tests  253 passed (253)
...
Functions    : 100% ( 54/54 )
Lines        : 100% ( 287/287 )
```

To see the library working in a browser:

```bash
pnpm demo    # then open http://localhost:5173, click "Approve & send"
```

Stop it with Ctrl-C when you are done (see the port trap above).

## 3. The full check

```bash
pnpm gate    # about 30s
```

This is exactly what CI runs (`.github/workflows/dagger.yml` calls the Dagger `ci`
function, which first checks the exact commit with a shared guard, then runs
`pnpm gate` in a Node 24 container). What `pnpm gate` runs, in order: Biome lint and
format check, TypeScript type checks (library and demo), Vitest unit tests with
coverage that must stay at 100% for lines, branches, functions and statements,
Playwright tests in real Chromium, then the build. If it passes locally, it should
pass in CI.

## 4. Map of the code

| Path | What it is |
| --- | --- |
| `src/index.ts` | The public API. Everything a user can import. Must stay browser-safe (no `node:` imports). |
| `src/detect/patterns.ts` | The detection rules: regexes, plus the small merchant and name lists. |
| `src/detect/checksums.ts` | Number checks: Luhn for cards, mod-97 for IBANs, SSA rules for bare SSNs. |
| `src/detect/detector.ts` | `detect()`: runs the rules and merges overlapping matches. |
| `src/redact.ts`, `src/vault.ts`, `src/rehydrate.ts` | Swap values for labels, hold the real values in memory, put them back. |
| `src/egress.ts` | `approve()`, `guardedProvider()` and the typed payload that providers require. |
| `src/egressReceipt.ts` | Optional signed receipts, and `DETECTOR_VERSION`. |
| `src/providers/` | `NoLLMProvider` (offline echo), `OpenRouterProvider`, `makeProvider`. |
| `test/` | Vitest unit tests. `detector-completeness.test.ts` checks every listed format at the network boundary. |
| `e2e/` | Playwright tests that drive the demo and fail if a real value appears in the outgoing request. |
| `examples/demo/` | The Vite browser demo. It uses only the public API. |

More on how these fit together: [Architecture](ARCHITECTURE.md).

## 5. Make your first change

A typical small change: teach the detector one more merchant name, say `Target`.
Test first.

1. Add a failing test. Create `test/first-change.test.ts`:

   ```ts
   import { describe, expect, it } from "vitest";
   import { detect } from "../src/index.js";

   describe("merchant dictionary", () => {
     it("finds Target as a merchant", () => {
       const spans = detect("Paid $5.00 at Target on 01/02/2026.");
       expect(
         spans.filter((s) => s.type === "MERCHANT").map((s) => s.value),
       ).toContain("Target");
     });
   });
   ```

2. Run just that test and watch it fail:

   ```bash
   pnpm exec vitest run test/first-change.test.ts   # about 1s, 1 failed
   ```

3. Add `"Target",` to the `MERCHANTS` list in `src/detect/patterns.ts`. Run the test
   again; it passes.

4. Run `pnpm gate`. It fails in `test/detector-version.test.ts`, on purpose: any change
   to the rules changes which ruleset a signed receipt was made with. Follow the
   comment in that test:
   - bump `DETECTOR_VERSION` in `src/egressReceipt.ts` (for example `"2"` to `"3"`),
   - add the new fingerprint the test printed under a new key in `RULESET_GOLDENS`
     (never edit an old one),
   - update the two assertions in that file that pin the current version.

5. Update [What it recognizes](DETECTION.md) so the docs match, add a line to
   `CHANGELOG.md`, run `pnpm lint:fix`, then `pnpm gate` again. We did exactly these
   steps on a fresh clone: 254 tests passed.

Changes that do not touch the rules (a bug fix in `rehydrate`, a provider option)
skip step 4.

## 6. Open a pull request

- Branch from `main` with a short prefix: `fix/…`, `feat/…`, `docs/…`, `ci/…`.
- Bug fixes start with a failing test that shows the bug. New behavior lands with its
  test in the same commit.
- Push and open a PR with `gh pr create`. CI (`dagger.yml`) runs `pnpm gate` against
  your exact commit. It must be green.
- Reviewers look for: tests that fail without your change, 100% coverage kept, nothing
  added to `src/index.ts` that should not be public, no `node:` import in browser code,
  and docs (README, [DETECTION.md](DETECTION.md), [API.md](API.md)) that still match
  what the code does. The rules the project will not bend are in
  [CONTRIBUTING.md](../CONTRIBUTING.md).
