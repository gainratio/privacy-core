# Using the library

The full API, with runnable examples: the four-step loop, the compile-time check, signed receipts, calling a real model, every export, and every setting. All examples were run against the published npm package, version 0.3.0. Back to the [README](../README.md).

## The full loop, step by step

You need [Node](https://nodejs.org) 22.13 or newer. Nothing else — no API key, no account, no
network call. Save this as `example.mjs` in any empty directory (it prints each step, including the audit log):

```js
import {
  approve, guardedProvider, NoLLMProvider, redactForEgress, rehydrate, Vault,
} from "@edgeproc/privacy-core";

const statement =
  "Grace Hopper, card 4242 4242 4242 4242, was charged $482.10 at Whole Foods on 01/14/2026.";

const vault = new Vault(); // holds your real values, in this process, on this machine
const audit = (e) => console.log("[audit]", e.kind, e.placeholders);

// 1. REDACT on-device. This is a proposal — no provider will accept it yet.
const pending = await redactForEgress(statement, vault, audit);
console.log("leaves your machine:", pending.redactedText);

// 2. APPROVE. You read the line above and say yes; only this mints a sendable payload.
const payload = approve(pending, audit);

// 3. SEND. NoLLMProvider is the built-in offline stand-in — no API key, no network.
const reply = await guardedProvider(new NoLLMProvider()).complete(payload);
console.log("model replied:", reply.redactedText);

// 4. REHYDRATE locally, bound to the vault the text was redacted with.
console.log("you read:", rehydrate(reply.redactedText, vault, payload.vaultRef));
```

Then:

```bash
npm install @edgeproc/privacy-core && node example.mjs
```

That prints, verbatim:

```text
[audit] redact [ '[NAME_1]', '[CARD_1]', '[AMOUNT_1]', '[MERCHANT_1]', '[DATE_1]' ]
leaves your machine: [NAME_1], card [CARD_1], was charged [AMOUNT_1] at [MERCHANT_1] on [DATE_1].
[audit] approve [ '[NAME_1]', '[CARD_1]', '[AMOUNT_1]', '[MERCHANT_1]', '[DATE_1]' ]
model replied: Summary (offline echo — no API key set):
I reviewed your statement. It referenced 5 redacted value(s): [NAME_1], [CARD_1], [AMOUNT_1], [MERCHANT_1], [DATE_1].
The first flagged value, [NAME_1], is the one to check.
(Set OPENROUTER_API_KEY + VITE_USE_OPENROUTER=1 to call a real model via the dev proxy.)
you read: Summary (offline echo — no API key set):
I reviewed your statement. It referenced 5 redacted value(s): Grace Hopper, 4242 4242 4242 4242, $482.10, Whole Foods, 01/14/2026.
The first flagged value, Grace Hopper, is the one to check.
(Set OPENROUTER_API_KEY + VITE_USE_OPENROUTER=1 to call a real model via the dev proxy.)
```

Step 2 is the one people skip. `redactForEgress` returns a *proposal*, not something you can send.
Nothing becomes sendable until `approve()` — and that holds even when the detector finds nothing,
because "found nothing" is not the same as "someone said yes". Provider adapters accept only the
type `approve()` mints, so passing one a raw string is
[a compile error](#the-part-that-makes-leaking-a-compile-error), not a code-review comment.

To swap the offline stand-in for a real model, see
[Calling a real model](#calling-a-real-model). For a signed record of every allow and deny, see
[Receipts](#receipts-a-record-of-what-was-allowed-and-what-was-blocked).

## The part that makes leaking a compile error

The rule "don't send raw text to the model" isn't a convention here, and it isn't
a runtime check you could forget to call. Provider adapters accept **only** a
branded `RedactedPayload` type, and the only thing that mints one is the
redaction pipeline (`redactForEgress` → `approve`). A plain `string` is not
assignable to it, so this:

```ts
import { NoLLMProvider } from "@edgeproc/privacy-core";

const provider = new NoLLMProvider();
await provider.complete("my card is 4242 4242 4242 4242");
```

fails before it ever runs:

```text
oops.ts(4,25): error TS2345: Argument of type 'string' is not assignable to parameter of type 'RedactedPayload'.
  Type 'string' is not assignable to type 'Branded<"RedactedPayload">'.
```

TypeScript's brand disappears at runtime, so the same guarantee is enforced a
second way: every approved payload is registered by object identity, and
`assertApproved()` rejects a hand-built or spread-cloned look-alike before any
network call — that's the `UnapprovedPayloadError` in the receipts example
below. `pnpm build` re-proves the compile-time half on every build.

## Receipts: a record of what was allowed and what was blocked

Receipts are **opt-in**. Hand `guardedProvider` a governance context — a
provider name, your signing key, and an `onReceipt` callback — and from then on
every decision it makes is signed into a **receipt**: a small record saying
"text with this fingerprint was allowed (or refused) to go to this provider",
signed with your key. Refusals are recorded too, so a blocked send can't just
vanish. A receipt never contains the text itself, only a SHA-256 hash of it.

Omit that argument and you get exactly the same redaction and the same
fail-closed guard — just no receipt. Turn receipts on when you need to prove
afterwards what left the device; leave them off when you don't.

Receipts are tamper-evident records, not replay-prevention tokens. The signed
Avow envelope is deterministic, so two identical decisions produce identical
receipts; a downstream audit store must track receipt occurrences if it needs
to count sends rather than only verify their content.

Signing and verifying live in `@edgeproc/avow`, so add it alongside:
`npm install @edgeproc/avow`.

```js
import { generateSeedHex, publicKeyHex, verifySignature } from "@edgeproc/avow";
import {
  approve,
  guardedProvider,
  NoLLMProvider,
  redactForEgress,
  Vault,
} from "@edgeproc/privacy-core";

const seedHex = generateSeedHex(); // your signing key, generated on this device
const receipts = [];

const provider = guardedProvider(new NoLLMProvider(), {
  provider: "offline-echo",
  seedHex,
  onReceipt: (r) => receipts.push(r),
});

const vault = new Vault();
const pending = await redactForEgress("Card on file: 4242 4242 4242 4242", vault);
await provider.complete(approve(pending, () => {}));

// A payload the guard never approved is refused — and the refusal is recorded too.
// (In TypeScript this call wouldn't even compile; plain JS shows the runtime half.)
await provider
  .complete({ redactedText: "raw card 4242 4242 4242 4242", vaultRef: { id: "x" } })
  .catch((err) => console.log("refused:", err.constructor.name));

for (const r of receipts) console.log(r.payload);

// Anyone holding your public key can check the receipts were not edited later.
await verifySignature(receipts[0], await publicKeyHex(seedHex));
console.log("\nsignature check: passed");
```

```text
refused: UnapprovedPayloadError
{
  action: 'llm.egress',
  provider: 'offline-echo',
  args_digest: 'sha256:091a3728dd5622843e14ffb925abcec1bd1cb5ad6461154ab0893b68f63d50b1',
  decision: 'allow',
  detector_version: '2'
}
{
  action: 'llm.egress',
  provider: 'offline-echo',
  args_digest: 'sha256:6726c6222d515ab998abb62680724ca993157f40a9021ab0643d0e967f4b417b',
  decision: 'deny',
  detector_version: '2'
}

signature check: passed
```

**What a receipt is worth, precisely.** A signature proves a record has not been
altered *since it was signed*. It says nothing about whether the machine that
signed it was already compromised at the time. If an attacker controls the host,
they can make it sign a true-looking record of a decision you never wanted.
Receipts give you tamper-evidence after the fact, not a trustworthy host.

## Calling a real model

The library is environment-agnostic: you pass your own key in, and it is never
read from the environment for you. The bundled demo keeps `OPENROUTER_API_KEY`
server-side — a same-origin dev proxy injects it, so it never reaches the browser
bundle. Copy `.env.example` → `examples/demo/.env`, set the key, add
`VITE_USE_OPENROUTER=1`, and re-run `pnpm demo`.

## See it in a browser

Clone this repo and run the demo, which does the same loop with a live preview
of exactly what will be sent:

```bash
pnpm install && pnpm demo   # then open http://localhost:5173
```

![Paste a statement, preview exactly what leaves, send only labels, read a rehydrated answer.](assets/demo.png)

Open your browser's network tab and watch the request. Only labels go out.
Nothing is sent until you click **Approve & send** — you approve the exact
outgoing text, not a promise about it.

To prove it without a browser window, `pnpm test:e2e` drives the same loop in
real Chromium, intercepts the outbound request, and fails if any real value
appears in it.

## Public API

Everything `src/index.ts` exports, and nothing more:

| Export | Kind | Role |
|---|---|---|
| `detect` | fn | deterministic identifier span detection |
| `approve` | fn | explicit review step → mints the sendable payload (audit sink required) |
| `assertApproved` | fn | runtime half of the guard — rejects unminted payloads |
| `guardedProvider` | fn | wrap a provider so the runtime guard runs at one chokepoint — plus receipts if given a governance context |
| `LlmProvider` | interface | provider contract — accepts only `RedactedPayload` |
| `PendingRedaction` | type | a redaction proposal awaiting explicit review — not yet sendable |
| `RedactedPayload` | type | the branded egress type |
| `unsafeBypass` | fn | the explicit, audited escape hatch |
| `buildEgressSubject` | fn | build the signed subject (hash of redacted text, decision, provider) |
| `contentHash` | fn | the canonical hash a verifier recomputes `args_digest` with |
| `DETECTOR_VERSION` | const | version tag for the detector ruleset, recorded in each receipt |
| `EgressDecision` | type | the guard's verdict on one egress attempt — allow or deny |
| `EgressGovernance` | interface | how a guarded provider seals its decisions (signer seed + receipt sink) |
| `EgressSubject` | type | the signed, hash-only record of one egress decision |
| `EgressSubjectInput` | interface | what the caller supplies to build an `EgressSubject` |
| `sealEgressReceipt` | fn | sign one egress decision into a receipt |
| `makeProvider` | fn | config-driven provider selector |
| `ProviderConfig` | interface | host-supplied config (API key, model, endpoint, timeout and response budget) for `makeProvider` |
| `SelectedProvider` | interface | the provider `makeProvider` picked, plus a label for the UI |
| `NoLLMProvider` | class | offline echo provider |
| `OpenRouterConfig` | interface | config for `OpenRouterProvider` (API key, model, endpoint, timeout and response budget) |
| `OpenRouterProvider` | class | OpenAI-compatible provider |
| `DEFAULT_OPENROUTER_TIMEOUT_MS` | const | default OpenRouter deadline (30 seconds) |
| `DEFAULT_OPENROUTER_MAX_RESPONSE_BYTES` | const | default OpenRouter response cap (1 MiB UTF-8) |
| `MAX_REDACTION_INPUT_BYTES` | const | UTF-8 input budget enforced before detection (512 KiB) |
| `redactForEgress` | fn | detect → vault-write → brand → a `PendingRedaction` proposal |
| `rehydrate` | fn | restore real values locally from placeholders |
| `AuditEntry` | type | one append-only audit record — a discriminated union of the three below |
| `RedactAuditEntry` | interface | audit record for a redact step |
| `ApproveAuditEntry` | interface | audit record for an approve step |
| `UnsafeBypassAuditEntry` | interface | audit record for an explicit unsafe-bypass |
| `AuditSink` | type | the audit callback signature callers supply to `approve`/`unsafeBypass` |
| `EntityType` | type | the identifier categories the detector recognizes (CARD, SSN, EMAIL, ...) |
| `RedactedResponse` | interface | a provider's reply, still in placeholder form until rehydrated |
| `Span` | interface | one detected identifier span (type, value, start, end) |
| `VaultRef` | interface | opaque handle to a vault's token → value mappings |
| `Vault` | class | reversible token↔value map |

Typed fail-closed errors are exported too, all extending the `PrivacyCoreError`
base class: `ForgedPayloadError`, `InputTooLargeError`, `MalformedProviderResponseError`,
`MissingApiKeyError`, `PlaceholderCollisionError`, `ProviderResponseTooLargeError`,
`ProviderTimeoutError`, `ResidualValueError`, `UnapprovedPayloadError`,
`UnresolvedPlaceholderError`, `VaultMismatchError`.

The brand factory (`mintPendingRedaction`) and the `SYNTHETIC_STATEMENT` fixture
are intentionally **not** on the front door — a payload can be earned, not
forged, and a fixture is never shipped by accident.

## Configuration

The library reads no environment variables; your code passes every setting in.

| Setting | Where | Default | What it changes |
| --- | --- | --- | --- |
| `apiKey` | `OpenRouterConfig` / `ProviderConfig` | — (required for OpenRouter) | the key sent to OpenRouter; keep it server-side (the demo uses a same-origin proxy) |
| `model` | `OpenRouterConfig` / `ProviderConfig` | `openai/gpt-4o-mini` via `makeProvider` | which model answers |
| `endpoint` | `OpenRouterConfig` / `ProviderConfig` | `https://openrouter.ai/api/v1/chat/completions` | any OpenAI-compatible chat/completions URL |
| `timeoutMs` | `OpenRouterConfig` / `ProviderConfig` | `30000` | end-to-end request deadline |
| `maxResponseBytes` | `OpenRouterConfig` / `ProviderConfig` | `1048576` (1 MiB) | largest reply accepted |
| `allowOffline` | `ProviderConfig` | `false` | lets `makeProvider` fall back to the offline echo when no key is set |
| `MAX_REDACTION_INPUT_BYTES` | constant | 512 KiB | input budget; larger input is refused |

The demo app reads `OPENROUTER_API_KEY` and `VITE_USE_OPENROUTER=1` from `examples/demo/.env`
(copy `.env.example`). Secrets are never committed.

