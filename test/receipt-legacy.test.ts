import {
  PayloadHashMismatch,
  publicKeyHex,
  ReceiptSchemaMismatch,
} from "@edgeproc/avow";
import { describe, expect, it } from "vitest";
import {
  type StoredEgressReceipt,
  sealEgressReceipt,
  verifyEgressReceipt,
} from "../src/index.js";

const SEED_HEX =
  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

const INPUT = {
  provider: "openrouter",
  redactedText: "Email [EMAIL_1] about SSN [SSN_1].",
  decision: "allow",
} as const;

/** A current receipt with its `schema` field removed, as 0.2.x stored it. */
async function legacyReceipt(): Promise<StoredEgressReceipt> {
  const { schema: _dropped, ...legacy } = await sealEgressReceipt(
    INPUT,
    SEED_HEX,
  );
  return legacy;
}

describe("verifyEgressReceipt", () => {
  it("labels a current receipt as not legacy", async () => {
    const receipt = await sealEgressReceipt(INPUT, SEED_HEX);
    await expect(
      verifyEgressReceipt(receipt, await publicKeyHex(SEED_HEX)),
    ).resolves.toEqual({ legacy: false });
  });

  it('labels a receipt with no schema field as legacy "pre-v1-schema"', async () => {
    await expect(
      verifyEgressReceipt(await legacyReceipt(), await publicKeyHex(SEED_HEX)),
    ).resolves.toEqual({ legacy: true, compat: "pre-v1-schema" });
  });

  it("rejects a receipt carrying any other schema value", async () => {
    const receipt = { ...(await legacyReceipt()), schema: "avow.receipt/v0" };
    await expect(
      verifyEgressReceipt(receipt, await publicKeyHex(SEED_HEX)),
    ).rejects.toBeInstanceOf(ReceiptSchemaMismatch);
  });

  it("rejects a schema field that is present but undefined", async () => {
    // Untyped input (e.g. a JS caller); the type forbids this shape.
    const receipt = {
      ...(await legacyReceipt()),
      schema: undefined,
    } as unknown as StoredEgressReceipt;
    await expect(
      verifyEgressReceipt(receipt, await publicKeyHex(SEED_HEX)),
    ).rejects.toBeInstanceOf(ReceiptSchemaMismatch);
  });

  it("still rejects a legacy receipt whose payload was tampered", async () => {
    const legacy = await legacyReceipt();
    const tampered = {
      ...legacy,
      payload: { ...legacy.payload, provider: "attacker" },
    };
    await expect(
      verifyEgressReceipt(tampered, await publicKeyHex(SEED_HEX)),
    ).rejects.toBeInstanceOf(PayloadHashMismatch);
  });
});
