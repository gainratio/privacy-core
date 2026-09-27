# Quickstart

Two ways in. If you just want to see what the library does, start with the
[README](../README.md) — it has a copy-pasteable Node script and its real
output. This page is for running the demo app and the repo's checks.

## Run the browser demo (no API key needed)

```bash
# Prereqs: Node >= 22.13, pnpm (pinned via packageManager). From the repo root:
pnpm install && pnpm demo
```

Open <http://localhost:5173>. A synthetic bank statement is pre-loaded. You see
the raw text, the exact text that will be sent (every **recognized** value
replaced by a label like `[CARD_1]` — the
[coverage table](DETECTION.md) is the precise list of
what that includes), and — after you click **Approve & send** — the answer with
your real values put back locally. With no key set, a built-in offline stand-in
model (`NoLLMProvider`) is used, so the whole loop runs with nothing on the
network.

Reviewing that middle pane is not decoration: it is how anything outside the
coverage table gets caught.

Open the browser's network tab while you click. Only labels go out.

**Stop the demo when you are done** (`Ctrl-C` in that terminal). It holds port
5173, and the e2e suite reuses an already-running server on that port instead of
starting its own. A demo server left over from this section was started WITHOUT
the settings the e2e run needs, so the suite would silently adopt the wrong
server and fail. If a run fails unexpectedly, check the port first:

```bash
lsof -ti tcp:5173   # any output means a server is still up — stop it, then re-run
```

## Call a real model

Copy `.env.example` → `examples/demo/.env`, set `OPENROUTER_API_KEY`, and add
`VITE_USE_OPENROUTER=1`. The demo then routes through a same-origin dev proxy
that injects the key server-side — it never reaches the browser bundle. Either
way, only labels cross the wire.

## Prove it without watching

```bash
pnpm exec playwright install --with-deps chromium   # first time only
pnpm test:e2e
```

Drives the demo in real Chromium, intercepts the outbound request, and fails if
any real value appears in it. The screenshot lands in the gitignored
`test-results/`.

## Run the full check suite

```bash
pnpm gate
```

Biome lint/format → typecheck → Vitest (with coverage thresholds) → Playwright
e2e → build. CI runs this exact command.
