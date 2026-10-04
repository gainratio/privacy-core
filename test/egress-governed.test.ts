import {
  publicKeyHex,
  type SignedReceipt,
  verifySignature,
} from "@gainratio/avow";
import { describe, expect, it } from "vitest";
import {
  approve,
  contentHash,
  DETECTOR_VERSION,
  type EgressGovernance,
  type EgressSubject,
  guardedProvider,
  type LlmProvider,
  type RedactedPayload,
  UnapprovedPayloadError,
} from "../src/index.js";
import { redactForEgress } from "../src/redact.js";
import type { RedactedResponse } from "../src/types.js";
import { Vault } from "../src/vault.js";

const SEED_HEX =
  "0101010101010101010101010101010101010101010101010101010101010101";

/** A provider that records whether it was actually reached. */
function spyProvider(): LlmProvider & { calls: RedactedPayload[] } {
  const calls: RedactedPayload[] = [];
  return {
    calls,
    async complete(payload): Promise<RedactedResponse> {
      calls.push(payload);
      return { redactedText: payload.redactedText };
    },
  };
}

function collector(): {
  governance: (provider: string) => EgressGovernance;
  receipts: SignedReceipt<EgressSubject>[];
} {
  const receipts: SignedReceipt<EgressSubject>[] = [];
  return {
    receipts,
    governance: (provider) => ({
      provider,
      seedHex: SEED_HEX,
      onReceipt: (r) => {
        receipts.push(r);
      },
    }),
  };
}

describe("guardedProvider as a governed egress boundary", () => {
  it("an approved egress reaches the provider AND emits a verifiable allow receipt", async () => {
    const inner = spyProvider();
    const { governance, receipts } = collector();
    const guarded = guardedProvider(inner, governance("openrouter"));

    const payload = approve(
      await redactForEgress("Pay Ada Lovelace now.", new Vault()),
      () => {},
    );
    const res = await guarded.complete(payload);

    expect(res.redactedText).toContain("[NAME_1]");
    expect(inner.calls).toHaveLength(1); // the send happened
    expect(receipts).toHaveLength(1);
    const receipt = receipts[0];
    if (!receipt) throw new Error("no receipt");
    expect(receipt.payload.decision).toBe("allow");
    expect(receipt.payload.provider).toBe("openrouter");
    await expect(
      verifySignature(receipt, await publicKeyHex(SEED_HEX)),
    ).resolves.toBeUndefined();
  });

  it("a denied/fail-closed egress SENDS NOTHING and emits a verifiable denial", async () => {
    const inner = spyProvider();
    const { governance, receipts } = collector();
    const guarded = guardedProvider(inner, governance("openrouter"));

    // A structurally valid but never-approved payload (forgery / bypassed guard).
    const forged = {
      redactedText: "Pay [NAME_1] now.",
      vaultRef: { id: "forged" },
      approvedAt: Date.now(),
    } as unknown as RedactedPayload;

    await expect(guarded.complete(forged)).rejects.toThrow(
      UnapprovedPayloadError,
    );
    expect(inner.calls).toHaveLength(0); // nothing left the device

    expect(receipts).toHaveLength(1);
    const receipt = receipts[0];
    if (!receipt) throw new Error("no denial receipt");
    expect(receipt.payload.decision).toBe("deny");
    // The denial digests the ATTEMPTED redacted text, and only its hash.
    expect(receipt.payload.args_digest).toBe(
      await contentHash({ redactedText: "Pay [NAME_1] now." }),
    );
    await expect(
      verifySignature(receipt, await publicKeyHex(SEED_HEX)),
    ).resolves.toBeUndefined();
  });

  it("records malformed runtime payloads as denials instead of losing the receipt", async () => {
    const inner = spyProvider();
    const { governance, receipts } = collector();
    const guarded = guardedProvider(inner, governance("openrouter"));

    await expect(
      guarded.complete(null as unknown as RedactedPayload),
    ).rejects.toThrow(UnapprovedPayloadError);

    expect(inner.calls).toHaveLength(0);
    expect(receipts).toHaveLength(1);
    const receipt = receipts[0];
    if (!receipt) throw new Error("no denial receipt");
    expect(receipt.payload.decision).toBe("deny");
    expect(receipt.payload.args_digest).toBe(
      await contentHash({ redactedText: "<invalid-payload>" }),
    );
    await expect(
      verifySignature(receipt, await publicKeyHex(SEED_HEX)),
    ).resolves.toBeUndefined();

    const hostile = Object.defineProperty({}, "redactedText", {
      get: () => {
        throw new Error("hostile getter");
      },
    });
    await expect(
      guarded.complete(hostile as unknown as RedactedPayload),
    ).rejects.toThrow(UnapprovedPayloadError);
    expect(receipts).toHaveLength(2);
    const hostileReceipt = receipts[1];
    if (!hostileReceipt) throw new Error("no hostile denial receipt");
    await expect(
      verifySignature(hostileReceipt, await publicKeyHex(SEED_HEX)),
    ).resolves.toBeUndefined();

    await expect(
      guarded.complete({ redactedText: 42 } as unknown as RedactedPayload),
    ).rejects.toThrow(UnapprovedPayloadError);
    expect(receipts).toHaveLength(3);
  });

  it("a pinned detectorVersion is recorded in the sealed receipt", async () => {
    // Pin a value that is NOT the default, or this test cannot tell a working
    // pin from one that is silently ignored.
    const PINNED = "pinned-test-ruleset";
    expect(PINNED).not.toBe(DETECTOR_VERSION);
    const inner = spyProvider();
    const receipts: SignedReceipt<EgressSubject>[] = [];
    const guarded = guardedProvider(inner, {
      provider: "openrouter",
      seedHex: SEED_HEX,
      detectorVersion: PINNED,
      onReceipt: (r) => {
        receipts.push(r);
      },
    });

    const payload = approve(
      await redactForEgress("hello", new Vault()),
      () => {},
    );
    await guarded.complete(payload);

    expect(receipts[0]?.payload.detector_version).toBe(PINNED);
  });

  it("awaits an async onReceipt before completing the send", async () => {
    const inner = spyProvider();
    let onReceiptDone = false;
    const guarded = guardedProvider(inner, {
      provider: "openrouter",
      seedHex: SEED_HEX,
      onReceipt: async () => {
        // Defer the flag to a macrotask. A guard that AWAITS onReceipt resolves
        // only after this fires; the fire-and-forget bug resolves before it, so
        // the flag is still false when complete() returns.
        await new Promise((resolve) => setTimeout(resolve, 0));
        onReceiptDone = true;
      },
    });
    const payload = approve(
      await redactForEgress("hello", new Vault()),
      () => {},
    );

    await guarded.complete(payload);

    // The receipt sink's async work has fully settled by the time the send
    // completed — an unawaited onReceipt would leave this false.
    expect(onReceiptDone).toBe(true);
    expect(inner.calls).toHaveLength(1);
  });

  it("without governance, guardedProvider keeps its original guard-only behavior", async () => {
    const inner = spyProvider();
    const guarded = guardedProvider(inner);
    const forged = {
      redactedText: "x",
      vaultRef: { id: "f" },
      approvedAt: 0,
    } as unknown as RedactedPayload;
    await expect(guarded.complete(forged)).rejects.toThrow(
      UnapprovedPayloadError,
    );
    expect(inner.calls).toHaveLength(0);
  });
});
