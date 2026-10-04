/**
 * Egress decisions, sealed as signed, tamper-evident receipts.
 *
 * The Egress Guard already gates whether redacted text may leave the device
 * (see {@link file://./egress.ts}). This module makes that decision *provable*:
 * an allow or deny is expressed as a small governed record — an
 * `EgressSubject` — and signed into a tamper-evident receipt via the shared
 * `@edgeproc/avow` signing envelope. A holder of the signer's public key can later
 * verify exactly which egress decisions were taken, without ever seeing the
 * content.
 *
 * SCOPE — sealing is opt-in: receipts are produced only for a
 * {@link file://./egress.ts guardedProvider} that was given an
 * {@link EgressGovernance} context. A caller who omits it still gets the full
 * redaction and the same fail-closed guard, just no receipt. The guarantee
 * below therefore reads: *once governed*, every allow and every deny at that
 * chokepoint is sealed.
 *
 * INVARIANT — no plaintext in a receipt: the subject stores only
 * `args_digest = sha256(canonical({ redactedText }))`, never the text itself,
 * and never the raw PII the vault holds. A receipt records *that* a decision
 * happened over *this* content, not the content.
 */

import {
  contentHash,
  RECEIPT_SCHEMA,
  type SignedReceipt,
  signPayload,
  verifySignature,
} from "@edgeproc/avow";

// Re-exported so receipt verifiers can recompute `args_digest` with the SAME
// canonical hash the sealer used, without importing @edgeproc/avow directly.
export { contentHash } from "@edgeproc/avow";

/** Whether the guard let the redacted text leave the device, or refused it. */
export type EgressDecision = "allow" | "deny";

/**
 * The governed effect: sending redacted text to a named provider was either
 * allowed or denied. A type alias (not an interface) so it satisfies the
 * `@edgeproc/avow` `JsonValue` constraint via TypeScript's implicit index
 * signature — the subject IS a plain JSON object.
 */
export type EgressSubject = {
  readonly action: "llm.egress";
  readonly provider: string;
  readonly args_digest: string;
  readonly decision: EgressDecision;
  readonly detector_version: string;
};

/**
 * Version tag for the Tier-1 deterministic detector ruleset. Bumping the
 * ruleset bumps this so a verifier can tell which detector version screened
 * the content behind a receipt.
 *
 * - "1": the ruleset shipped through 0.2.x.
 * - "2": 0.3.0 — Unicode-aware email; dashed and spaced SSNs (ungated, as the
 *   dashed form was in 0.2.x) plus unseparated SSNs gated on the SSA issuance
 *   rules; and the NANP phone set.
 *
 * `test/detector-version.test.ts` pins each version to a fingerprint of the
 * ruleset, so a rule change without a bump fails the gate.
 */
export const DETECTOR_VERSION = "2";

/** What the caller knows at the egress decision point. */
export interface EgressSubjectInput {
  readonly provider: string;
  /** The redacted (already-scrubbed) text — hashed, never stored verbatim. */
  readonly redactedText: string;
  readonly decision: EgressDecision;
  readonly detectorVersion?: string;
}

/** Build the signed subject, digesting the redacted text and nothing else. */
export async function buildEgressSubject(
  input: EgressSubjectInput,
): Promise<EgressSubject> {
  return {
    action: "llm.egress",
    provider: input.provider,
    args_digest: await contentHash({ redactedText: input.redactedText }),
    decision: input.decision,
    detector_version: input.detectorVersion ?? DETECTOR_VERSION,
  };
}

/**
 * How a guarded provider seals its decisions. Given to
 * {@link file://./egress.ts guardedProvider}, every allow AND every fail-closed
 * deny at that chokepoint is signed and handed to `onReceipt` — the guard
 * cannot act silently once governed.
 */
export interface EgressGovernance {
  /** Provider name recorded in each receipt (e.g. "openrouter"). */
  readonly provider: string;
  /** Ed25519 seed (hex) that signs the receipts. */
  readonly seedHex: string;
  /**
   * Receives every sealed decision receipt. May be async (e.g. it persists the
   * receipt); the guard awaits it, so the send does not complete until the
   * receipt has been durably handled.
   */
  readonly onReceipt: (
    receipt: SignedReceipt<EgressSubject>,
  ) => void | Promise<void>;
  readonly detectorVersion?: string;
}

/** Seal an egress decision into a signed, pinned-key-verifiable receipt. */
export async function sealEgressReceipt(
  input: EgressSubjectInput,
  seedHex: string,
): Promise<SignedReceipt<EgressSubject>> {
  return signPayload(await buildEgressSubject(input), seedHex);
}

/**
 * A receipt as it may sit in storage. Receipts sealed by 0.2.x (avow < 0.5)
 * have no `schema` field; current ones carry `"avow.receipt/v1"`.
 */
export type StoredEgressReceipt = Omit<
  SignedReceipt<EgressSubject>,
  "schema"
> & { readonly schema?: string };

/**
 * The outcome of a successful verify. `legacy: true` means the receipt had no
 * `schema` field and was checked as a pre-v1 receipt (`compat`
 * `"pre-v1-schema"`). Its signature, hash and signer were checked in full.
 */
export type EgressReceiptVerification =
  | { readonly legacy: false }
  | { readonly legacy: true; readonly compat: "pre-v1-schema" };

/**
 * Verify a stored egress receipt against a pinned signer key. Throws the same
 * coded avow errors as `verifySignature`.
 *
 * Keeps 0.2.x receipts verifiable: avow ^0.5 requires `schema:
 * "avow.receipt/v1"`, which is not part of the signed bytes. A receipt with
 * NO `schema` field gets that label before the check and is reported as
 * legacy. A receipt with any other `schema` value (including an explicit
 * `undefined`) goes to avow as-is and is rejected.
 */
export async function verifyEgressReceipt(
  receipt: StoredEgressReceipt,
  expectedPublicKey: string,
): Promise<EgressReceiptVerification> {
  const legacy = !Object.hasOwn(receipt, "schema");
  const envelope = legacy ? { ...receipt, schema: RECEIPT_SCHEMA } : receipt;
  await verifySignature(
    envelope as SignedReceipt<EgressSubject>,
    expectedPublicKey,
  );
  return legacy ? { legacy, compat: "pre-v1-schema" } : { legacy };
}
