import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * docs/API.md contract for legacy (0.2.x) receipts. Pins two facts:
 * avow ^0.5.3 itself verifies a receipt with no `schema` field, and the
 * `legacy` flag is advisory because `schema` is not in the signed payload.
 */
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const api = readFileSync(join(root, "docs/API.md"), "utf8").replace(
  /\s+/g,
  " ",
);

describe("docs/API.md legacy receipt contract", () => {
  it("says the legacy flag is advisory because schema is not signed", () => {
    expect(api).toContain(
      "The `legacy` flag is advisory only: `schema` is not part of the signed payload",
    );
  });

  it("does not claim avow ^0.5 rejects schema-less receipts", () => {
    expect(api).not.toMatch(/avow \^0\.5's `verifySignature` rejects them/);
  });
});
