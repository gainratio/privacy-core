import { detect } from "./detect/detector.js";
import { mintPendingRedaction, type PendingRedaction } from "./egress.js";
import {
  InputTooLargeError,
  PlaceholderCollisionError,
  ResidualValueError,
} from "./errors.js";
import type { AuditSink, Span } from "./types.js";
import type { Vault } from "./vault.js";

/**
 * The placeholder grammar (same shape `rehydrate` restores). Input containing
 * it would be indistinguishable from vault tokens after redaction.
 */
const PLACEHOLDER_SHAPE = /\[[A-Z]+_\d+\]/;

/** Maximum input size keeps synchronous detection bounded on the browser thread. */
export const MAX_REDACTION_INPUT_BYTES = 512 * 1024;
const UTF8_ENCODER = new TextEncoder();
const MAX_UTF8_BYTES_PER_CODE_UNIT = 3;

function exceedsInputCap(raw: string): boolean {
  if (raw.length * MAX_UTF8_BYTES_PER_CODE_UNIT <= MAX_REDACTION_INPUT_BYTES) {
    return false;
  }
  const probe = UTF8_ENCODER.encodeInto(
    raw,
    new Uint8Array(MAX_REDACTION_INPUT_BYTES + 1),
  );
  return probe.read < raw.length || probe.written > MAX_REDACTION_INPUT_BYTES;
}

/** Escape a raw value so it can be embedded literally inside a RegExp. */
function escapeForRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Match the value only as a STANDALONE token: no alphanumeric character may sit
 * immediately before or after it. This is the \b-style guard for values whose
 * edges are digits/letters (every label-gated ACCOUNT/ROUTING value is), and it
 * is what separates a real leak (`... 021000021` standalone) from a benign
 * superstring (`0123456789A`, `1002003009`) that merely contains the digits.
 * For a value whose own edge is a non-word char the adjacent guard is simply
 * inert there, degrading to a raw-presence check — safe, since such a value
 * cannot be a substring of a longer alphanumeric token anyway.
 */
function survivesAsToken(out: string, value: string): boolean {
  const standalone = new RegExp(
    `(?<![A-Za-z0-9])${escapeForRegExp(value)}(?![A-Za-z0-9])`,
  );
  return standalone.test(out);
}

/**
 * Fail closed if any detected value survived as a standalone token in the
 * redacted output. The span-by-span rebuild only removes the ranges the
 * detector matched, so a value that recurs where the ruleset did not
 * independently match it (a duplicate copy of a label-gated ACCOUNT/ROUTING
 * number) can slip through. A detected value is one the tool already vaulted as
 * PII; emitting a verbatim standalone copy would leak it, so refuse rather than
 * send. A value that survives only as a substring of a longer alphanumeric
 * token (a benign order id / tracking number) is NOT a leak and does not refuse.
 */
function assertNoResidual(out: string, spans: readonly Span[]): void {
  // One boundary-aware scan per DISTINCT value: an amount-heavy paste repeats
  // the same few values across many spans, and the check used to recompile and
  // re-scan the whole output once per span (quadratic on a 512 KiB input).
  const checked = new Set<string>();
  for (const s of spans) {
    if (checked.has(s.value)) continue;
    checked.add(s.value);
    if (survivesAsToken(out, s.value)) {
      throw new ResidualValueError(
        `a detected ${s.type} value survived redaction and would cross the wire ` +
          "verbatim (a duplicate the ruleset matched only once) — refusing to " +
          "emit a payload that leaks a value already known to be PII",
      );
    }
  }
}

/**
 * THE ONLY legitimate constructor of a PendingRedaction.
 *
 * Detects PII, writes each raw value into the vault, and replaces it with a
 * stable placeholder. The result is a review PROPOSAL — it is NOT sendable.
 * Only the explicit `approve()` step turns it into the RedactedPayload
 * capability a provider will accept, and that holds even when detection finds
 * nothing: zero detections never auto-approve.
 */
export async function redactForEgress(
  raw: string,
  vault: Vault,
  audit?: AuditSink,
): Promise<PendingRedaction> {
  if (exceedsInputCap(raw)) {
    throw new InputTooLargeError(MAX_REDACTION_INPUT_BYTES);
  }
  const collision = raw.match(PLACEHOLDER_SHAPE);
  if (collision) {
    throw new PlaceholderCollisionError(
      `input already contains placeholder-shaped text ("${collision[0]}") — ` +
        "redacting it would make restore ambiguous, so the redaction is refused",
    );
  }
  const spans = detect(raw);
  // Rebuild text left-to-right, swapping each span for its vault token.
  let out = "";
  let cursor = 0;
  const placeholders: string[] = [];
  for (const s of spans) {
    out += raw.slice(cursor, s.start);
    const token = vault.tokenize(s.type, s.value);
    out += token;
    placeholders.push(token);
    cursor = s.end;
  }
  out += raw.slice(cursor);
  // Fail closed BEFORE auditing/minting: a redact that leaks is not a redact.
  assertNoResidual(out, spans);
  audit?.({ kind: "redact", at: Date.now(), placeholders });
  return mintPendingRedaction(out, vault.ref, placeholders);
}
