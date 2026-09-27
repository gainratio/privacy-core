import { expect, test } from "@playwright/test";

/**
 * The redact → send → rehydrate loop, automated in a real (headless) browser,
 * driving the demo app (examples/demo) which consumes ONLY the library's
 * public API.
 *
 * We drive the OpenRouter provider path (VITE_USE_OPENROUTER=1, which routes
 * through the same-origin dev proxy) and intercept the request with `page.route`
 * BEFORE it reaches the proxy, so NOTHING leaves the machine. The interceptor is
 * the network-boundary proof: it inspects the exact bytes the app puts on the
 * wire and asserts only placeholders cross it.
 */

/** Raw PII from SYNTHETIC_STATEMENT — none of these may ever hit the wire. */
const RAW_VALUES = [
  "Ada Lovelace",
  "ada.lovelace@example.com",
  "(415) 555-0132",
  "123-45-6789",
  "000123456789",
  "021000021",
  "GB82 WEST 1234 5698 7654 32",
  "4242 4242 4242 4242",
  "Whole Foods",
  "$1,482.10",
];

/**
 * The formats a Node test with a spied `fetch` cannot vouch for.
 *
 * Unicode property escapes and `u`-flag regex semantics are engine-level
 * behaviour, and V8-in-Node is not the same execution path as V8-in-Chromium
 * (different source decoding, different ICU/locale wiring). These cases are
 * re-proved HERE, in a real browser, against the bytes the app actually puts on
 * the wire.
 *
 * `fragments` carries the lesson the unit suite learned the hard way: an
 * ASCII-only recognizer reduces `josé.álvarez@example.com` to `josé.á[EMAIL_1]`,
 * so a whole-value absence check ALONE would score a partial leak as a pass.
 */
const NEWLY_COVERED: ReadonlyArray<{
  readonly raw: string;
  readonly fragments: readonly string[];
}> = [
  { raw: "223456789", fragments: ["223456789"] }, // undashed SSN
  { raw: "234 56 7890", fragments: ["234 56 7890"] }, // space-separated SSN
  {
    raw: "josé.álvarez@example.com", // non-ASCII local part
    fragments: ["josé", "álvarez"],
  },
  {
    raw: "kontakt@münchen-bank.example", // IDN domain
    fragments: ["kontakt", "münchen-bank"],
  },
  { raw: "415-555-0148", fragments: ["415-555-0148", "555-0148"] }, // hyphenated
  { raw: "212.555.0187", fragments: ["212.555.0187", "555.0187"] }, // dotted
  { raw: "+1 646 555 0143", fragments: ["646 555 0143", "555 0143"] }, // +1
  { raw: "912-70-1234", fragments: ["912-70-1234", "70-1234"] }, // dashed ITIN
  {
    raw: "+1(415) 555-0199", // +1 glued to the parenthesized area code
    fragments: ["(415) 555-0199", "555-0199"],
  },
  {
    raw: "4111 1111 1111 1111", // card followed by its expiry (Luhn retry)
    fragments: ["4111 1111 1111 1111", "1111 1111"],
  },
  { raw: "415-555-0177", fragments: ["555-0177"] }, // phone glued to "x12"
  { raw: "345.67.8901", fragments: ["67.8901", "8901"] }, // dot-separated SSN
  {
    raw: "5555 5555 5555 4444", // card after another digit group ("#2")
    fragments: ["5555 4444"],
  },
  { raw: "760-04-7660", fragments: ["04-7660", "7660"] }, // SSN after a ref
];

/** Every raw value and identifying fragment that must never cross the wire. */
const ALL_LEAKS = [
  ...RAW_VALUES,
  ...NEWLY_COVERED.flatMap((c) => [c.raw, ...c.fragments]),
];

/**
 * The NON-VACUITY half. Every "raw value is absent" assertion would pass
 * trivially on a fixture that simply did not contain these formats, so the wire
 * is REQUIRED to carry the placeholders the widened recognizers must mint:
 * five more SSNs, a second and third EMAIL, five more PHONEs and two more CARDs.
 */
const REQUIRED_TOKENS = [
  "[SSN_2]",
  "[SSN_3]",
  "[SSN_4]",
  "[SSN_5]",
  "[SSN_6]",
  "[EMAIL_2]",
  "[EMAIL_3]",
  "[PHONE_2]",
  "[PHONE_3]",
  "[PHONE_4]",
  "[PHONE_5]",
  "[PHONE_6]",
  "[CARD_2]",
  "[CARD_3]",
];

const SUCCESS_TEXT =
  "Done. The provider only saw placeholders; real values were restored locally.";

/**
 * Confirm we are driving THIS demo before asserting anything about it.
 *
 * `reuseExistingServer` adopts whatever is already listening on :5173. When that
 * turned out to be an unrelated project's dev server, every locator missed and
 * the failure read as "element(s) not found" — a confusing message for a
 * wrong-server problem. A named check turns that into an obvious one. (The
 * QUICKSTART documents the port collision; this makes the suite say so too.)
 */
async function assertDemoIsMounted(page: import("@playwright/test").Page) {
  await expect(
    page.locator("h1"),
    "the server on :5173 is not the privacy-core demo — stop the other one (lsof -ti tcp:5173)",
  ).toHaveText("EdgeProc Privacy Core");
}

test("redact → send → rehydrate: only placeholders cross the wire", async ({
  page,
}) => {
  let wireBody = "";

  // A clean console is part of "it works". Anything the detector path logs —
  // a regex construction failure under a different engine would surface here —
  // fails the test rather than scrolling past.
  const consoleProblems: string[] = [];
  page.on("console", (msg) => {
    if (msg.type() === "error" || msg.type() === "warning") {
      consoleProblems.push(`${msg.type()}: ${msg.text()}`);
    }
  });
  page.on("pageerror", (err) =>
    consoleProblems.push(`pageerror: ${err.message}`),
  );

  // Register the interceptor BEFORE goto so it catches the send. The canned
  // OpenAI-compatible reply echoes placeholders so local rehydration has
  // tokens to restore.
  await page.route("**/openrouter/**", async (route) => {
    wireBody = route.request().postData() ?? "";

    // NETWORK-BOUNDARY PROOF: placeholders present, raw PII absent.
    expect(wireBody).toContain("[NAME_1]");
    expect(wireBody).toContain("[CARD_1]");
    // Non-vacuity: the widened recognizers actually fired in Chromium.
    for (const token of REQUIRED_TOKENS) {
      expect(wireBody, `expected ${token} on the wire`).toContain(token);
    }
    for (const raw of ALL_LEAKS) {
      expect(wireBody, `raw value leaked on the wire: ${raw}`).not.toContain(
        raw,
      );
    }

    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        choices: [
          {
            message: {
              content:
                "Reviewed [NAME_1]'s statement; largest charge [AMOUNT_1].",
            },
          },
        ],
      }),
    });
  });

  await page.goto("/");
  await assertDemoIsMounted(page);

  // Pre-send proof, in the RENDERED DOM: the wire pane is the user's view of
  // "exactly what leaves the device", so it must already show placeholders and
  // none of the raw values.
  //
  // Scoped to #wire deliberately. The redaction-set pane (#set) shows each raw
  // value beside its token ON PURPOSE — that is the review UI, and the whole
  // design depends on the user seeing what is about to be swapped out. Asserting
  // raw values are absent page-wide would be asserting the review UI is broken.
  const wire = page.locator("#wire");
  await expect(wire).toContainText("[NAME_1]");
  await expect(wire).toContainText("[CARD_1]");
  for (const token of REQUIRED_TOKENS) {
    await expect(wire).toContainText(token);
  }
  for (const raw of ALL_LEAKS) {
    await expect(wire).not.toContainText(raw);
  }

  // The send button IS the explicit approval step — say so on its face.
  await expect(page.locator("#send")).toContainText("Approve");
  await page.locator("#send").click();

  // Wait for the loop to finish.
  await expect(page.locator("#status")).toHaveText(SUCCESS_TEXT);

  // The interceptor fired (wire bytes captured) — guards against a silent
  // provider-path miss.
  expect(wireBody.length).toBeGreaterThan(0);

  // Rehydration proof: real values restored locally in the answer pane.
  const answer = page.locator("#answer");
  await expect(answer).toContainText("Ada Lovelace");
  await expect(answer).toContainText("$1,482.10");

  // Clean console for the whole flow — no errors, no warnings.
  expect(consoleProblems, consoleProblems.join("\n")).toEqual([]);

  // Write to the gitignored artifacts dir so test runs never churn the tree.
  // The committed README hero (docs/assets/demo.png) is a stable, decoupled snapshot.
  await page.screenshot({
    path: "test-results/redact-send-rehydrate.png",
    fullPage: true,
  });
});

test("egress receipts + fail-closed refusal are demonstrable in the demo", async ({
  page,
}) => {
  // Canned OpenAI-compatible reply for the approved (allow) send.
  await page.route("**/openrouter/**", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        choices: [{ message: { content: "Reviewed [NAME_1]'s statement." } }],
      }),
    });
  });

  await page.goto("/");
  await assertDemoIsMounted(page);

  // Turn ON receipt signing so every guard decision is sealed.
  await page.locator("#receipts-toggle").check();

  // 1) Fail-closed refusal: attempt to send a payload that was NEVER approved.
  await page.locator("#try-unapproved").click();
  await expect(page.locator("#answer")).toContainText("Refused (fail-closed)");
  // With receipts on, the refusal itself is sealed as a signed DENY receipt.
  const denyReceipt = page.locator("#receipts .receipt");
  await expect(denyReceipt).toHaveCount(1);
  await expect(denyReceipt.first()).toContainText("DENY");
  await expect(denyReceipt.first()).toContainText("signed ✓");

  // 2) An approved send is sealed as a signed ALLOW receipt.
  await page.locator("#send").click();
  await expect(page.locator("#status")).toHaveText(SUCCESS_TEXT);
  const allowReceipt = page.locator("#receipts .receipt");
  await expect(allowReceipt).toHaveCount(1);
  await expect(allowReceipt.first()).toContainText("ALLOW");
  await expect(allowReceipt.first()).toContainText("signed ✓");
});
