/**
 * `@gainratio/privacy-core` — a browser-side privacy boundary for LLM calls.
 *
 * Raw private text stays on-device; only policy-approved, redacted text can
 * reach a provider; the model's reply is rehydrated locally. The load-bearing
 * idea is the type-enforced Egress Guard: provider adapters accept ONLY a
 * branded {@link RedactedPayload}, so handing raw text to a provider is a
 * compile error.
 *
 * This barrel is the PRODUCTION surface. Test fixtures live behind the
 * `@gainratio/privacy-core/testing` subpath, never here.
 */

// Detection spine.
export { detect } from "./detect/detector.js";
// The egress boundary.
export {
  approve,
  assertApproved,
  guardedProvider,
  type LlmProvider,
  type PendingRedaction,
  type RedactedPayload,
  unsafeBypass,
} from "./egress.js";
// Signed egress receipts.
export {
  buildEgressSubject,
  contentHash,
  DETECTOR_VERSION,
  type EgressDecision,
  type EgressGovernance,
  type EgressReceiptVerification,
  type EgressSubject,
  type EgressSubjectInput,
  type StoredEgressReceipt,
  sealEgressReceipt,
  verifyEgressReceipt,
} from "./egressReceipt.js";
// Typed fail-closed errors.
export {
  ForgedPayloadError,
  InputTooLargeError,
  MalformedProviderResponseError,
  MissingApiKeyError,
  PlaceholderCollisionError,
  PrivacyCoreError,
  ProviderResponseTooLargeError,
  ProviderTimeoutError,
  ResidualValueError,
  UnapprovedPayloadError,
  UnresolvedPlaceholderError,
  VaultMismatchError,
} from "./errors.js";
export {
  makeProvider,
  type ProviderConfig,
  type SelectedProvider,
} from "./providers/factory.js";
// Providers.
export { NoLLMProvider } from "./providers/nollm.js";
export {
  DEFAULT_OPENROUTER_MAX_RESPONSE_BYTES,
  DEFAULT_OPENROUTER_TIMEOUT_MS,
  type OpenRouterConfig,
  OpenRouterProvider,
} from "./providers/openrouter.js";
// The reversible loop.
export {
  MAX_REDACTION_INPUT_BYTES,
  redactForEgress,
} from "./redact.js";
export { rehydrate } from "./rehydrate.js";
// Public domain types.
export type {
  ApproveAuditEntry,
  AuditEntry,
  AuditSink,
  EntityType,
  RedactAuditEntry,
  RedactedResponse,
  Span,
  UnsafeBypassAuditEntry,
  VaultRef,
} from "./types.js";
export { Vault } from "./vault.js";
