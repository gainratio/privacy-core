import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { MERCHANTS, NAMES, RULES } from "../src/detect/patterns.js";
import { buildEgressSubject, DETECTOR_VERSION } from "../src/egressReceipt.js";
import { DETECTOR_VERSION as PUBLIC_DETECTOR_VERSION } from "../src/index.js";

/**
 * A deterministic fingerprint of the Tier-1 ruleset: every rule's type, regex
 * source + flags, and the NAME of its accept-gate, in `RULES` order (order is
 * the overlap tie-break, so it is part of the ruleset), plus both dictionaries.
 *
 * A rule's scan mode and the NAME of its shorter-candidate function are
 * included when present. It deliberately does not hash the checksum function bodies — their source
 * text is formatter-sensitive — so a change *inside* `luhnValid`/`ibanValid`/
 * `ssnValid` must be caught by review, not by this guard. Adding, removing,
 * reordering, or re-gating a rule, editing a pattern, or editing a dictionary
 * all change the fingerprint.
 */
function rulesetFingerprint(): string {
  const canonical = JSON.stringify({
    rules: RULES.map((r) => [
      r.type,
      r.re.source,
      r.re.flags,
      r.accept?.name ?? null,
      // Scan mode and retry candidates change what a rule finds, so they are
      // part of the ruleset. Appended only when present, so a rule without
      // them hashes exactly as it did when "1" was computed.
      ...(r.scan || r.shorter ? [r.scan ?? null, r.shorter?.name ?? null] : []),
    ]),
    merchants: MERCHANTS,
    names: NAMES,
  });
  return `sha256:${createHash("sha256").update(canonical, "utf8").digest("hex")}`;
}

/**
 * One golden fingerprint per detector version ever sealed into a receipt.
 * Append-only: a shipped version's fingerprint is history and never edited.
 *
 * - "1": the ruleset shipped through 0.2.2 (ASCII-only email, dashed-only SSN,
 *   `(415) 555-0132`-only phone). Computed from `src/detect/patterns.ts` at the
 *   v0.2.2 tag with this same function.
 * - "2": 0.3.0 — Unicode email; SSN written with any one consistent separator
 *   (dash, dot, whitespace, Unicode dash) ungated, plus an unseparated 9-digit
 *   SSN gated on `ssnValid`; NANP phone (unrestricted parenthesized branch,
 *   `2-9`-gated bare branch, both ending at `(?!\d)`); CARD as a print-layout
 *   grammar scanned at every start with word-closing retries, beside the
 *   v0.2.2 loose rule; IBAN scanned at every start with mod-97-valid,
 *   word-closing retries (registry length, or 15+ for an unregistered country); ROUTING/ACCOUNT with a named `value` group (ACCOUNT 6-17
 *   digits), ordered before SSN. (Recomputed four times before 0.3.0 shipped, after
 *   the pre-release security reviews — "2" was never sealed into a published
 *   receipt with any other ruleset.)
 */
const RULESET_GOLDENS: Readonly<Record<string, string>> = {
  "1": "sha256:3b6b79ace54f87e6ffb25c7a7567a621bdae41007cc614d302b390b891e058c6",
  "2": "sha256:8129e8f323e666a0639030073d666f6ed2dcd74ab9cb036d29de381577159500",
  // "3": the loose card recognizer also scans at every start, so a
  // mixed-separator card after a digit group is no longer hidden by a rejected
  // greedy candidate.
  "3": "sha256:a5d64af459e83b6bd20d6ac15d10dfc0e112285d24090f69f28ed200db3e5b6d",
};

describe("detector version (which ruleset screened a sealed receipt)", () => {
  it("is 2 for the 0.3.0 ruleset, on the module and the public barrel", () => {
    expect(DETECTOR_VERSION).toBe("3");
    expect(PUBLIC_DETECTOR_VERSION).toBe("3");
  });

  it("is what an unpinned receipt payload carries", async () => {
    const subject = await buildEgressSubject({
      provider: "openrouter",
      redactedText: "Email [EMAIL_1] about SSN [SSN_1].",
      decision: "allow",
    });
    expect(subject.detector_version).toBe("3");
  });

  it("is tied to the current ruleset: change a rule, bump the version", () => {
    // If this fails you changed the detection ruleset. Bump DETECTOR_VERSION
    // in src/egressReceipt.ts and APPEND the new fingerprint here — never
    // overwrite a shipped version's golden.
    expect(rulesetFingerprint()).toBe(RULESET_GOLDENS[DETECTOR_VERSION]);
  });

  it("never reuses a fingerprint across versions", () => {
    const fingerprints = Object.values(RULESET_GOLDENS);
    expect(new Set(fingerprints).size).toBe(fingerprints.length);
  });
});
