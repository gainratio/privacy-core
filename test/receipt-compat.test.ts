import {
  PayloadHashMismatch,
  publicKeyHex,
  type SignedReceipt,
  verifySignature,
} from "@edgeproc/avow";
import { describe, expect, it } from "vitest";
import {
  buildEgressSubject,
  contentHash,
  type EgressSubject,
  sealEgressReceipt,
} from "../src/index.js";

/**
 * Receipts sealed by 0.2.x must keep verifying after the move to
 * `@edgeproc/avow` ^0.4.1 — the CHANGELOG promises it, so a fixed vector
 * proves it.
 *
 * Provenance of the vectors: produced by the PUBLISHED
 * `@edgeproc/privacy-core@0.2.2` from npm (the old name), resolved against `@edgeproc/avow@0.1.0`
 * (the version its lockfile pinned), by calling its `sealEgressReceipt` with
 * the seed below. They are frozen here verbatim; nothing in this file derives
 * them from the current code.
 */
const SEED_HEX =
  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

const V022_VECTORS: ReadonlyArray<{
  readonly redactedText: string;
  readonly receipt: SignedReceipt<EgressSubject>;
}> = [
  {
    redactedText: "Email [EMAIL_1] about SSN [SSN_1].",
    receipt: {
      payload: {
        action: "llm.egress",
        provider: "openrouter",
        args_digest:
          "sha256:b5bbf57767487920890c0421641ce30ea488eddb3aec5bc221dbbadd0c34082e",
        decision: "allow",
        detector_version: "1",
      },
      payload_hash:
        "sha256:6d926da06232594aac431712636f08ca09f7d738b1a69038855fd78aed8af44a",
      public_key:
        "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
      signature:
        "fb044f7ff013244157392e06119a0f103b13c69a6231641ec573da8e0c24c581c33b4d91eead3027b9834ad957323ca7035d4b8919ebe591e7b27be6a567e300",
    },
  },
  {
    redactedText: "Refund [CARD_1] please.",
    receipt: {
      payload: {
        action: "llm.egress",
        provider: "openrouter",
        args_digest:
          "sha256:47efb279c08cb69e2e0d34cce6edf91aacf960af56b88464d91868d532bccd43",
        decision: "deny",
        detector_version: "1",
      },
      payload_hash:
        "sha256:048a7d56638751d34253cb72debfe2d14725535ed8ea9d72a209b8818b5f0bf5",
      public_key:
        "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
      signature:
        "249b2e5c6dfd4b482fbe33242bc5b55f7bd739f63cf315dd179136e5b54e6d6fd7865959afb27bb5d93c09fba13906fec69acb3d46ed141cbe0c0ff13e5ef50e",
    },
  },
];

describe("0.2.x receipts verify under @edgeproc/avow ^0.4.1", () => {
  for (const { redactedText, receipt } of V022_VECTORS) {
    const label = receipt.payload.decision;

    it(`verifies the frozen 0.2.2 ${label} receipt against its pinned key`, async () => {
      const pinned = await publicKeyHex(SEED_HEX);
      expect(pinned).toBe(receipt.public_key);
      await expect(verifySignature(receipt, pinned)).resolves.toBeUndefined();
    });

    it(`re-seals the same ${label} decision to byte-identical output`, async () => {
      // Same canonical bytes, same hash, same deterministic Ed25519 signature:
      // a 0.3.0 sealer pinned to detector "1" is indistinguishable from 0.2.2.
      expect(await contentHash({ redactedText })).toBe(
        receipt.payload.args_digest,
      );
      const input = {
        provider: "openrouter",
        redactedText,
        decision: receipt.payload.decision,
        detectorVersion: "1",
      };
      expect(await buildEgressSubject(input)).toEqual(receipt.payload);
      expect(await sealEgressReceipt(input, SEED_HEX)).toEqual(receipt);
    });

    it(`still rejects the ${label} receipt once its payload is tampered`, async () => {
      const tampered = {
        ...receipt,
        payload: { ...receipt.payload, provider: "attacker" },
      };
      await expect(
        verifySignature(tampered, receipt.public_key),
      ).rejects.toBeInstanceOf(PayloadHashMismatch);
    });
  }
});
