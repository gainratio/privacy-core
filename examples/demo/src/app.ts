import {
  approve,
  detect,
  type EgressGovernance,
  guardedProvider,
  type LlmProvider,
  makeProvider,
  type RedactedPayload,
  redactForEgress,
  rehydrate,
  type Span,
  Vault,
} from "@gainratio/privacy-core";
import { SYNTHETIC_STATEMENT } from "@gainratio/privacy-core/testing";
import "./styles.css";

interface Refs {
  readonly input: HTMLTextAreaElement;
  readonly setList: HTMLElement;
  readonly wire: HTMLElement;
  readonly answer: HTMLElement;
  readonly status: HTMLElement;
  readonly send: HTMLButtonElement;
  readonly receiptsToggle: HTMLInputElement;
  readonly receipts: HTMLElement;
  readonly tryUnapproved: HTMLButtonElement;
}

// The browser NEVER holds the OpenRouter key. When VITE_USE_OPENROUTER=1, the
// app talks to the same-origin dev proxy (see vite.config.ts), which injects the
// server-side key. The `apiKey` below is only a non-secret sentinel that selects
// the OpenRouter code path; the endpoint points at the local proxy.
const useOpenRouter = import.meta.env.VITE_USE_OPENROUTER === "1";
const { provider, label } = makeProvider({
  apiKey: useOpenRouter ? "via-dev-proxy" : undefined,
  model: import.meta.env.VITE_OPENROUTER_MODEL,
  endpoint: useOpenRouter ? "/openrouter/api/v1/chat/completions" : undefined,
  // No key means run the offline echo — opt in explicitly so a genuinely
  // missing production key fails closed instead of silently downgrading.
  allowOffline: !useOpenRouter,
});

// A FIXED, documented NON-SECRET seed, used only to sign DEMO receipts in the
// browser so the receipts pane is reproducible. A real deployment keeps its
// signing seed server-side and never ships it to the client.
const DEMO_SEED =
  "0101010101010101010101010101010101010101010101010101010101010101";

function escapeHtml(s: string): string {
  return s.replace(
    /[&<>"]/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c] ?? c,
  );
}

/** A structural view of the fields a signed receipt exposes for display. */
interface DisplayReceipt {
  readonly payload: {
    readonly decision: string;
    readonly provider: string;
    readonly args_digest: string;
  };
  readonly signature: string;
  readonly public_key: string;
}

/** Append one sealed decision receipt to the receipts pane. */
function appendReceipt(refs: Refs, receipt: DisplayReceipt): void {
  const { decision, provider: prov, args_digest } = receipt.payload;
  const li = document.createElement("li");
  li.className = `receipt receipt-${decision}`;
  li.innerHTML =
    `<code>${escapeHtml(decision.toUpperCase())}</code> ` +
    `<span class="raw">${escapeHtml(prov)}</span> ` +
    `<em>digest ${escapeHtml(args_digest.slice(0, 22))}… · signed ✓</em>`;
  refs.receipts.appendChild(li);
}

/** Governance that seals every allow/deny at the guard into a signed receipt. */
function governance(refs: Refs): EgressGovernance {
  return {
    provider: label,
    seedHex: DEMO_SEED,
    onReceipt: (r) => appendReceipt(refs, r),
  };
}

/** The plain provider, or the governed (receipt-sealing) wrapper when toggled on. */
function activeProvider(refs: Refs): LlmProvider {
  return refs.receiptsToggle.checked
    ? guardedProvider(provider, governance(refs))
    : provider;
}

/** Render the redaction set: each token, its raw value (escaped), and its type. */
function renderSet(refs: Refs, spans: readonly Span[], vault: Vault): void {
  const seen = new Set<string>();
  const rows: string[] = [];
  for (const s of spans) {
    const token = vault.tokenize(s.type, s.value); // stable; reuses existing token
    if (seen.has(token)) continue;
    seen.add(token);
    rows.push(
      `<li><code>${escapeHtml(token)}</code> ← <span class="raw">${escapeHtml(s.value)}</span> <em>${s.type}</em></li>`,
    );
  }
  refs.setList.innerHTML = rows.join("");
}

/** Live preview: show the redaction set + exact wire text BEFORE approval. */
async function refreshPreview(refs: Refs): Promise<void> {
  try {
    const vault = new Vault();
    const spans = detect(refs.input.value);
    const pending = await redactForEgress(refs.input.value, vault);
    refs.wire.textContent = pending.redactedText;
    renderSet(refs, spans, vault);
  } catch (err) {
    // Fail closed, visibly: e.g. input already contains placeholder-shaped
    // text ([CARD_1]), which would make restore ambiguous.
    refs.wire.textContent = `Refused: ${String(err)}`;
    refs.setList.replaceChildren();
  }
}

/** redact → review → APPROVE (the click) → send → rehydrate, fresh vault per run. */
async function runLoop(refs: Refs): Promise<void> {
  refs.send.disabled = true;
  refs.receipts.replaceChildren();
  refs.status.textContent = "Redacting on-device…";
  const vault = new Vault();
  try {
    const spans = detect(refs.input.value);
    const pending = await redactForEgress(refs.input.value, vault);
    refs.wire.textContent = pending.redactedText;
    renderSet(refs, spans, vault);
    // The click on "Approve & send" IS the explicit review action: the user
    // has seen the redaction set + exact wire payload above. Nothing is
    // sendable until this line runs — zero detections included.
    const payload = approve(pending, () => {});
    refs.status.textContent = `Approved. Sending redacted text to ${label}…`;
    const res = await activeProvider(refs).complete(payload);
    // Bind the restore to the vault the payload was redacted with.
    refs.answer.textContent = rehydrate(
      res.redactedText,
      vault,
      payload.vaultRef,
    );
    refs.status.textContent =
      "Done. The provider only saw placeholders; real values were restored locally.";
  } catch (err) {
    refs.answer.textContent = `Error: ${String(err)}`;
    refs.status.textContent = "Error (see answer pane).";
  } finally {
    refs.send.disabled = false;
  }
}

/**
 * Demonstrate the runtime egress guard: attempt to send a payload that was NEVER
 * approved (a forged capability, as a buggy or hostile caller would build). Every
 * provider calls assertApproved first, so the send is refused fail-closed and
 * nothing leaves the device — and with receipts on, the refusal is itself sealed
 * as a signed DENY receipt.
 */
async function tryUnapproved(refs: Refs): Promise<void> {
  refs.receipts.replaceChildren();
  const forged = {
    redactedText: "Pay [NAME_1] now — never reviewed.",
    vaultRef: { id: "forged-never-approved" },
    approvedAt: Date.now(),
  } as unknown as RedactedPayload;
  try {
    await activeProvider(refs).complete(forged);
    refs.answer.textContent =
      "UNEXPECTED: a never-approved payload was accepted — this would be a bug.";
    refs.status.textContent = "Guard FAILED (see answer pane).";
  } catch (err) {
    refs.answer.textContent = `Refused (fail-closed): ${String(err)}`;
    refs.status.textContent =
      "The egress guard rejected an unapproved payload — nothing left the device.";
  }
}

function queryRef<T extends HTMLElement>(root: HTMLElement, sel: string): T {
  const el = root.querySelector<T>(sel);
  if (!el) throw new Error(`missing element: ${sel}`);
  return el;
}

function buildRefs(root: HTMLElement): Refs {
  return {
    input: queryRef<HTMLTextAreaElement>(root, "#input"),
    setList: queryRef(root, "#set"),
    wire: queryRef(root, "#wire"),
    answer: queryRef(root, "#answer"),
    status: queryRef(root, "#status"),
    send: queryRef<HTMLButtonElement>(root, "#send"),
    receiptsToggle: queryRef<HTMLInputElement>(root, "#receipts-toggle"),
    receipts: queryRef(root, "#receipts"),
    tryUnapproved: queryRef<HTMLButtonElement>(root, "#try-unapproved"),
  };
}

export function mountApp(root: HTMLElement): void {
  root.innerHTML = TEMPLATE.replace("{{provider}}", escapeHtml(label));
  const refs = buildRefs(root);
  refs.input.value = SYNTHETIC_STATEMENT;
  refs.input.addEventListener("input", () => void refreshPreview(refs));
  refs.send.addEventListener("click", () => void runLoop(refs));
  refs.tryUnapproved.addEventListener("click", () => void tryUnapproved(refs));
  void refreshPreview(refs);
}

const TEMPLATE = `
  <header>
    <h1>EdgeProc Privacy Core</h1>
    <p>Raw text stays on your device. Only redacted placeholders reach the provider,
       then the answer is rehydrated locally. Provider: <strong>{{provider}}</strong></p>
  </header>
  <main>
    <section>
      <h2>1 · Paste sensitive text</h2>
      <textarea id="input" spellcheck="false"></textarea>
    </section>
    <section>
      <h2>2 · Review &amp; approve — exactly what will leave the device</h2>
      <p class="hint">Redaction set:</p>
      <ul id="set" class="set"></ul>
      <p class="hint">Wire payload (sent verbatim — open your network tab to confirm):</p>
      <pre id="wire" class="wire"></pre>
      <label class="toggle">
        <input type="checkbox" id="receipts-toggle" />
        Sign egress receipts (seal every allow/deny decision)
      </label>
      <div class="actions">
        <button id="send">Approve &amp; send redacted text →</button>
        <button id="try-unapproved" class="danger">Try to send WITHOUT approval (see it refused)</button>
      </div>
      <p id="status" class="status"></p>
    </section>
    <section>
      <h2>Egress receipts (signed, tamper-evident)</h2>
      <p class="hint">Turn on “Sign egress receipts”, then send (an <code>allow</code>)
         or try an unapproved send (a <code>deny</code>) to see each decision sealed.</p>
      <ul id="receipts" class="set"></ul>
    </section>
    <section>
      <h2>3 · Locally-rehydrated answer (real values restored)</h2>
      <pre id="answer" class="answer"></pre>
    </section>
  </main>
`;
