import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { RULES } from "../src/detect/patterns.js";
import {
  detect,
  type EntityType,
  redactForEgress,
  rehydrate,
  Vault,
} from "../src/index.js";

/**
 * Regressions found by the 0.3.0 security review, which ran the v0.2.2 and the
 * 0.3.0 `src/detect` trees side by side. Every input below was REDACTED by
 * v0.2.2 (or, for the checksum-retry block, is a real identifier with trailing
 * text) and leaked from the first 0.3.0 candidate. Each one must stay redacted.
 */

/** The characters of `value` inside `text` that no detected span covers. */
function leakedChars(text: string, value: string): string {
  const at = text.indexOf(value);
  if (at === -1) throw new Error(`fixture bug: ${value} not in ${text}`);
  const spans = detect(text);
  let leaked = "";
  for (let i = at; i < at + value.length; i++) {
    if (!spans.some((s) => s.start <= i && i < s.end)) leaked += text[i];
  }
  return leaked;
}

/**
 * Best-of-three `detect()` milliseconds per repeated `unit` at `size`
 * characters, measured in a child Node process with no coverage
 * instrumentation (see test/support/detect-timing.mjs).
 */
function timeDetectUninstrumented(
  size: number,
  units: readonly string[],
  ceilingMs: number,
): Record<string, number> {
  const script = fileURLToPath(
    new URL("./support/detect-timing.mjs", import.meta.url),
  );
  const env = { ...process.env };
  delete env.NODE_V8_COVERAGE;
  delete env.NODE_OPTIONS;
  const child = spawnSync(
    process.execPath,
    [
      "--experimental-strip-types",
      "--disable-warning=ExperimentalWarning",
      script,
      String(size),
      JSON.stringify(units),
      String(ceilingMs),
    ],
    { encoding: "utf8", env, timeout: 50_000 },
  );
  // A quadratic scan never finishes 512 KiB: the spawn timeout kills it.
  expect(child.error?.message, "detect() timing child").toBeUndefined();
  expect(child.status, child.stderr).toBe(0);
  return JSON.parse(child.stdout) as Record<string, number>;
}

function valuesOf(text: string, type: EntityType): string[] {
  return detect(text)
    .filter((s) => s.type === type)
    .map((s) => s.value);
}

describe("dashed and spaced SSNs are redacted without the issuance gate", () => {
  // v0.2.2 redacted every `ddd-dd-dddd`. ITINs (area 9xx) are real taxpayer
  // IDs, and a value that fails the SSA issuance rules is still far more likely
  // to be an identifier than anything else when it is written in SSN shape.
  const dashed = [
    ["ITIN", "912-70-1234"],
    ["ITIN", "987-65-4321"],
    ["area 9xx", "900-12-3456"],
    ["area 666", "666-12-3456"],
    ["area 000", "000-12-3456"],
    ["group 00", "123-00-4567"],
    ["serial 0000", "123-45-0000"],
    ["textbook", "123-45-6789"],
    ["Woolworth", "078-05-1120"],
  ] as const;

  for (const [label, value] of dashed) {
    it(`redacts a dashed ${label} value: ${value}`, () => {
      expect(valuesOf(`ITIN ${value} on file.`, "SSN")).toEqual([value]);
    });
  }

  const spaced = [
    "912 70 1234",
    "666 12 3456",
    "000 12 3456",
    "123 00 4567",
    "123 45 0000",
  ] as const;

  for (const value of spaced) {
    it(`redacts a spaced SSN-shaped value: ${value}`, () => {
      expect(valuesOf(`SSN ${value} on file.`, "SSN")).toEqual([value]);
    });
  }

  it("still gates the bare 9-digit form (routing numbers stay out)", () => {
    for (const value of ["912701234", "666123456", "123004567", "021000021"]) {
      expect(valuesOf(`Reference ${value} filed.`, "SSN"), value).toEqual([]);
    }
    expect(valuesOf("Reference 123456789 filed.", "SSN")).toEqual([
      "123456789",
    ]);
  });
});

describe("parenthesized phone numbers keep every v0.2.2 shape", () => {
  const cases = [
    ["country code glued to the parenthesis", "+1(415) 555-0132"],
    ["bare 1 glued to the parenthesis", "1(415) 555-0132"],
    ["NBSP after the area code", "(415)\u00a0555-0132"],
    ["tab after the area code", "(415)\t555-0132"],
    ["newline after the area code", "(415)\n555-0132"],
    ["em space after the area code", "(415)\u2003555-0132"],
    ["area code starting 1", "(123) 456-7890"],
    ["exchange starting 1", "(415) 155-0132"],
    ["area code starting 0", "(012) 055-0132"],
    ["no separator after the parenthesis", "(415)555-0132"],
    ["digit immediately before the parenthesis", "5(415) 555-0132"],
  ] as const;

  for (const [label, value] of cases) {
    it(`redacts ${label}: ${JSON.stringify(value)}`, () => {
      expect(leakedChars(`Call ${value} today.`, value)).toBe(
        value.startsWith("5(") ? "5" : "",
      );
    });
  }

  it("keeps the whole +1 prefix inside the span", () => {
    expect(valuesOf("Call +1(415) 555-0132 today.", "PHONE")).toEqual([
      "+1(415) 555-0132",
    ]);
    expect(valuesOf("Call +1 (415) 555-0132 today.", "PHONE")).toEqual([
      "+1 (415) 555-0132",
    ]);
  });

  it("keeps every shape the widened 0.3.0 pattern gained", () => {
    for (const value of [
      "415-555-0132",
      "212.555.0187",
      "415 555 0132",
      "+1 646 555 0143",
      "1-415-555-0132",
      "+1.415.555.0132",
      "(415)-555-0132",
      "(415).555.0132",
      "(415) 555 0132",
    ]) {
      expect(valuesOf(`Call ${value} today.`, "PHONE"), value).toEqual([value]);
    }
  });

  it("keeps the NANP 2-9 rule on the unparenthesized form only", () => {
    for (const text of ["Ref 123-456-7890 filed", "Ref 415-155-0132 filed"]) {
      expect(valuesOf(text, "PHONE"), text).toEqual([]);
    }
  });
});

describe("a checksum-rejected match is retried shorter from the same start", () => {
  it("finds a card followed by an expiry fragment", () => {
    expect(valuesOf("card 4111 1111 1111 1111 12/27", "CARD")).toEqual([
      "4111 1111 1111 1111",
    ]);
  });

  it("finds a card followed by a CVV and more text", () => {
    expect(valuesOf("card 4111 1111 1111 1111 123 exp 12/27", "CARD")).toEqual([
      "4111 1111 1111 1111",
    ]);
  });

  it("finds an unspaced card followed by a short number", () => {
    expect(valuesOf("card 4111111111111111 43 due", "CARD")).toEqual([
      "4111111111111111",
    ]);
  });

  it("finds an IBAN followed by an uppercase word", () => {
    expect(valuesOf("IBAN GB82 WEST 1234 5698 7654 32 ABCD", "IBAN")).toEqual([
      "GB82 WEST 1234 5698 7654 32",
    ]);
  });

  it("never carves a shorter candidate out of a longer digit run", () => {
    // 4111111111111111 is Luhn-valid, but here it is the first 16 digits of a
    // 17-digit run. A shorter candidate must still end on a word boundary.
    expect(valuesOf("ref 41111111111111112 filed", "CARD")).toEqual([]);
  });

  it("keeps scanning after a shortened match", () => {
    expect(
      valuesOf("cards 4111 1111 1111 1111 12 and 4242 4242 4242 4242", "CARD"),
    ).toEqual(["4111 1111 1111 1111", "4242 4242 4242 4242"]);
  });

  it("still rejects a candidate with no valid shorter prefix", () => {
    expect(valuesOf("Card 4242 4242 4242 4241 is fake.", "CARD")).toEqual([]);
  });
});

/** Every identifier character in `text` must be inside some detected span. */
function allCovered(text: string, values: readonly string[]): string[] {
  return values
    .map((value) => [value, leakedChars(text, value)] as const)
    .filter(([, leaked]) => leaked !== "")
    .map(([value, leaked]) => `${value} leaked ${JSON.stringify(leaked)}`);
}

describe("overlapping spans merge into their union instead of dropping", () => {
  // Re-review of b6aea7d: the retry carved a Luhn-valid "card" out of a
  // reference number plus the next SSN's area code, and the overlap pass then
  // DROPPED the SSN span, so its tail went out bare. Coverage must be the
  // union of every rule's matches — an overlap may never uncover a character.
  const cases = [
    ["3852631216 760-04-7660", ["760-04-7660"]],
    ["896 38 9043 725-71-9450", ["725-71-9450"]],
    ["$123 45 6789", ["123 45 6789"]],
    ["$1(747)\t712-1349", ["(747)\t712-1349"]],
    [
      "(144).076-2191 4111-1111-1111-1111",
      ["(144).076-2191", "4111-1111-1111-1111"],
    ],
  ] as const;

  for (const [text, values] of cases) {
    it(`covers every identifier in ${JSON.stringify(text)}`, () => {
      expect(allCovered(text, values)).toEqual([]);
    });
  }

  it("keeps the earlier span's type and the exact union text as the value", () => {
    const spans = detect("Total $123 45 6789 due");
    expect(spans).toEqual([
      { type: "AMOUNT", value: "$123 45 6789", start: 6, end: 18 },
    ]);
  });

  it("round-trips a merged span through the vault", async () => {
    const vault = new Vault();
    const text = "Ref 3852631216 760-04-7660 and $123 45 6789 on file.";
    const pending = await redactForEgress(text, vault);
    for (const leak of ["7660", "04-7660", "45 6789", "6789"]) {
      expect(pending.redactedText).not.toContain(leak);
    }
    expect(rehydrate(pending.redactedText, vault, pending.vaultRef)).toBe(text);
  });
});

describe("a card preceded by another digit group is still found", () => {
  for (const text of [
    "(415) 555-0132 4111 1111 1111 1111",
    "SSN 123-45-6789 4111 1111 1111 1111",
    "#2 4111 1111 1111 1111",
    "Ref 12 4111 1111 1111 1111",
    "Order 7 4111-1111-1111-1111 paid",
    "code 0132 4242 4242 4242 4242",
  ]) {
    it(`finds the card in ${JSON.stringify(text)}`, () => {
      const card = text.match(/4[12]\d\d([ -])\d{4}\1\d{4}\1\d{4}/)?.[0];
      if (card === undefined) throw new Error("fixture bug");
      expect(leakedChars(text, card)).toBe("");
    });
  }

  it("finds a mixed-separator card after a digit group", () => {
    const text = "Order 7 4111 1111-1111 1111";
    expect(leakedChars(text, "4111 1111-1111 1111")).toBe("");
  });

  it("recognizes the card layouts people actually print", () => {
    for (const card of [
      "4111111111111111",
      "4111 1111 1111 1111",
      "4111-1111-1111-1111",
      "3782 822463 10005", // Amex 4-6-5
      "3782-822463-10005",
      "3056 930902 5904", // Diners 4-6-4
      "4222 2222 2222 2", // 13-digit Visa
      "6200 0000 0000 0000 000", // 19 digits (4-4-4-4-3)
    ]) {
      expect(valuesOf(`Card ${card} on file.`, "CARD"), card).toEqual([card]);
    }
  });
});

/** Complete `prefix` with the one check digit that makes it Luhn-valid. */
function luhnComplete(prefix: string): string {
  for (let check = 0; check < 10; check++) {
    const candidate = `${prefix}${check}`;
    let sum = 0;
    let double = false;
    for (let i = candidate.length - 1; i >= 0; i--) {
      let n = candidate.charCodeAt(i) - 48;
      if (double) n = n * 2 > 9 ? n * 2 - 9 : n * 2;
      sum += n;
      double = !double;
    }
    if (sum % 10 === 0) return candidate;
  }
  throw new Error("unreachable: some check digit always completes Luhn");
}

/** Lay `digits` out in `sizes` groups, cycling through `seps` between them. */
function layout(
  digits: string,
  sizes: readonly number[],
  seps: readonly string[],
): string {
  let out = "";
  let at = 0;
  sizes.forEach((size, k) => {
    if (k > 0) out += seps[(k - 1) % seps.length];
    out += digits.slice(at, at + size);
    at += size;
  });
  return out;
}

/**
 * Every layout v0.2.2's `(?:\d[ -]?){13,19}` redacted — mixed separators and
 * non-4-digit groupings included. The print-layout grammar alone missed ten of
 * these (0% redacted where v0.2.2 had 100%); the v0.2.2 rule now runs beside it.
 */
const V022_CARD_LAYOUTS: ReadonlyArray<
  readonly [string, string, readonly number[], readonly string[]]
> = [
  ["16 4-4-4-4 mixed", "411111111111111", [4, 4, 4, 4], [" ", "-", " "]],
  ["16 8-8", "455555555555555", [8, 8], [" "]],
  ["16 4-4-8", "545454545454545", [4, 4, 8], [" "]],
  ["16 4-12", "601100099013942", [4, 12], [" "]],
  ["16 6-10", "353011133330000", [6, 10], [" "]],
  ["15 amex mixed", "37828224631000", [4, 6, 5], [" ", "-"]],
  ["13 4-3-3-3", "422222222222", [4, 3, 3, 3], [" "]],
  ["19 6-13", "623456789012345678", [6, 13], [" "]],
  ["19 4-4-4-7", "411111111111111111", [4, 4, 4, 7], [" "]],
  ["18 4-4-4-6", "41111111111111111", [4, 4, 4, 6], [" "]],
  ["16 4-4-4-4", "411111111111111", [4, 4, 4, 4], [" "]],
  ["15 amex 4-6-5", "37828224631000", [4, 6, 5], ["-"]],
];

describe("every card layout v0.2.2 redacted is still redacted", () => {
  for (const [label, prefix, sizes, seps] of V022_CARD_LAYOUTS) {
    it(`redacts a standalone ${label} card`, () => {
      const card = layout(luhnComplete(prefix), sizes, seps);
      const text = `Card: ${card}.`;
      expect(leakedChars(text, card), card).toBe("");
      expect(valuesOf(text, "CARD"), card).toContain(card);
    });
  }
});

describe("the remaining format limits the review found", () => {
  it("redacts a phone number glued to an extension", () => {
    expect(valuesOf("Call 415-555-0132x12 today", "PHONE")).toEqual([
      "415-555-0132",
    ]);
    expect(valuesOf("Call (415) 555-0132ext. 7", "PHONE")).toEqual([
      "(415) 555-0132",
    ]);
    // Still never the middle of a longer digit run.
    expect(valuesOf("Ref 415-555-01329 filed", "PHONE")).toEqual([]);
  });

  it("redacts SSNs written with any one consistent separator", () => {
    for (const ssn of [
      "123.45.6789",
      "123\u00a045\u00a06789",
      "123\u201345\u20136789", // en dash
      "123\u201445\u20146789", // em dash
      "123\u201045\u20106789", // hyphen
      "123\u221245\u22126789", // minus sign
      "912-70-1234",
    ]) {
      expect(valuesOf(`SSN ${ssn} on file`, "SSN"), ssn).toEqual([ssn]);
    }
    // Mixed separators are not an SSN shape.
    expect(valuesOf("Part 123-45.6789 shipped", "SSN")).toEqual([]);
  });

  it("redacts long labelled account numbers", () => {
    for (const account of ["123456", "1234567890123", "12345678901234567"]) {
      expect(
        valuesOf(`Account number: ${account} debited`, "ACCOUNT"),
        account,
      ).toEqual([account]);
    }
    // Five digits or fewer collide with years and amounts, which the
    // residual guard would then refuse to send; 18+ is not a bank account.
    expect(valuesOf("Account number: 20260 debited", "ACCOUNT")).toEqual([]);
    expect(
      valuesOf("Account number: 123456789012345678 debited", "ACCOUNT"),
    ).toEqual([]);
  });
});

/** A mod-97-valid IBAN for `country` with this BBAN (check digits computed). */
function makeIban(country: string, bban: string): string {
  const digits = `${bban}${country}00`.replace(/[A-Z]/g, (c) =>
    String(c.charCodeAt(0) - 55),
  );
  let remainder = 0;
  for (const ch of digits) remainder = (remainder * 10 + Number(ch)) % 97;
  return `${country}${String(98 - remainder).padStart(2, "0")}${bban}`;
}

const grouped = (iban: string, sep: string) =>
  iban.replace(/(.{4})(?=.)/g, `$1${sep}`);

describe("an IBAN followed by more text is found for every country and separator", () => {
  // Final review of 00d9e6c: the country-length retry had no candidate for a
  // country missing from the ISO 13616 registry (MA, NC, PF and other
  // bank-issued codes), and counted only " " as a separator although the
  // pattern accepts any whitespace — so a tab- or NBSP-grouped IBAN followed
  // by a word was retried at the wrong length and leaked.
  const bban28 = "0110101234567890123456";
  const cases: ReadonlyArray<readonly [string, string, string]> = [
    ["registry country, spaces", makeIban("GB", "WEST12345698765432"), " "],
    ["registry country, tabs", makeIban("GB", "WEST12345698765432"), "\t"],
    ["registry country, NBSP", makeIban("DE", "370400440532013000"), "\u00a0"],
    [
      "registry country, newlines",
      makeIban("FR", "20041010050500013M02606"),
      "\n",
    ],
    ["unknown country MA", makeIban("MA", bban28.slice(0, 24)), " "],
    ["unknown country NC", makeIban("NC", "2004101005050001302606"), " "],
    [
      "unknown country PF, NBSP",
      makeIban("PF", "2004101005050001302606"),
      "\u00a0",
    ],
    ["unknown country XX, tabs", makeIban("XX", "1234567890123456"), "\t"],
  ];

  for (const [label, iban, sep] of cases) {
    it(`finds a ${label} IBAN followed by a word`, () => {
      const value = grouped(iban, sep);
      for (const tail of [" ABCD", " REF 7", `${sep}EUR`]) {
        const text = `IBAN ${value}${tail}`;
        expect(leakedChars(text, value), JSON.stringify(text)).toBe("");
      }
    });
  }

  it("still finds the same IBANs standalone and compact", () => {
    for (const [, iban] of cases) {
      expect(valuesOf(`IBAN ${iban}.`, "IBAN"), iban).toEqual([iban]);
    }
  });
});

describe("the shorter-candidate retry stays sound and linear", () => {
  const gated = RULES.filter((rule) => rule.accept !== undefined);

  it("only runs on gated patterns bounded by \\b, whose whole match is the value", () => {
    expect(gated.map((rule) => rule.type)).toEqual([
      "IBAN",
      "CARD",
      "CARD",
      "SSN",
    ]);
    for (const rule of gated) {
      expect(rule.re.source.startsWith("\\b"), rule.type).toBe(true);
      expect(rule.re.source.endsWith("\\b"), rule.type).toBe(true);
      // The retry re-tests the whole match, so a gated rule must not carve
      // its value out of a named `value` group the way the label rules do.
      expect(rule.re.source.includes("(?<value>"), rule.type).toBe(false);
    }
  });

  it("never lets any rule match the empty string (the scan must advance)", () => {
    for (const rule of RULES) {
      expect(
        new RegExp(rule.re.source, rule.re.flags).test(""),
        rule.type,
      ).toBe(false);
    }
  });

  it("scans 512 KiB of IBAN-, card- and email-shaped input in bounded time", () => {
    // Every `AB12`/`GB82` group starts an IBAN candidate. Re-testing ~7 shorter
    // prefixes at each start made this ~25x slower than v0.2.2 (1.2-1.6 s on
    // the browser thread); v0.2.2's email pattern was quadratic on a `1234-`
    // run (minutes at this size). The fixed scan takes ~100-250 ms per shape
    // uninstrumented.
    //
    // Two guards, because each misses what the other catches:
    // - an ABSOLUTE ceiling (1.5 s, ~6x the measured worst) on every shape,
    //   which catches a slowdown in the SHARED scan/merge code — that slows the
    //   reference too, so a ratio alone cannot see it;
    // - a RELATIVE bound (IBAN shapes < 3x a same-size card-shaped workload),
    //   which catches an IBAN-only regression on a runner fast enough to stay
    //   under the ceiling. Uninstrumented, the fix measures <= 1.4x; the
    //   pre-fix per-group IBAN retry (`shorter: wordClosingPrefixes`) measures
    //   3.9-5.4x, so a 4x bound would sometimes miss it and 3x does not.
    //
    // The timing runs in a plain Node child (test/support/detect-timing.mjs),
    // outside Vitest's coverage instrumentation, which slows these tight
    // loops several-fold and unevenly; each figure is best-of-three.
    const reference = "4111 1111 1111 1111 12 ";
    const iban = ["AB12 ", "GB82 A1 ", "AB12\t", "MA64 0110 "];
    const card = [reference, "4111 ", "4111-", "3782 822463 "];
    const email = ["1234-", "a.", "a.b@c.", "x@y.z "];
    const ceilingMs = 1500;
    const timings = timeDetectUninstrumented(
      512 * 1024,
      [...card, ...iban, ...email],
      ceilingMs,
    );
    for (const [unit, ms] of Object.entries(timings)) {
      expect(ms, JSON.stringify(unit)).toBeLessThan(ceilingMs);
    }
    for (const unit of iban) {
      const ratio = (timings[unit] ?? Number.NaN) / (timings[reference] ?? 0);
      expect(ratio, JSON.stringify(unit)).toBeLessThan(3);
    }
  }, 60_000);

  it("scans 64 KiB of rejected-then-retried candidates in well under 1.5s", () => {
    // Each unit forces a checksum rejection followed by a retry, or a gated
    // candidate at every group start. A blow-up
    // guard, not a benchmark: the bounded retry costs tens of milliseconds per
    // input here (a few hundred under coverage instrumentation on a loaded
    // runner), while a super-linear retry never finishes on 64 KiB at all.
    const size = 64 * 1024;
    for (const unit of [
      "4111 1111 1111 1111 12 ",
      "1 ",
      "2-",
      "GB82 WEST 1234 5698 7654 32 ABCD ",
      "GB00 A1B2 C3D4 E5F6 G7H8 I9J0 K1L2 M3 ",
      // Overlapping gated scan: a candidate starts at EVERY 4-digit group.
      "4111 ",
      "4111-",
      "3782 822463 ",
      "123.45.",
      "415-555-0132x",
    ]) {
      const hostile = unit.repeat(Math.ceil(size / unit.length)).slice(0, size);
      const started = performance.now();
      detect(hostile);
      expect(performance.now() - started, unit).toBeLessThan(1500);
    }
  });
});
