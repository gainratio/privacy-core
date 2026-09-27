# What it recognizes

The exact list of formats `@edgeproc/privacy-core` finds and replaces, and the ones it does not. Back to the [README](../README.md).

Detection is a fixed ruleset, so the honest version of "it finds the private
bits" is a list. This is the whole of it. If a format is not in the left column,
it is not detected, and the review step is what catches it.

| Type | Recognized | Not recognized |
| --- | --- | --- |
| `EMAIL` | any script, on both sides of the `@` — `ada@example.com`, `josé.álvarez@example.com`, `kontakt@münchen-bank.example` | a domain with no dot (`user@localhost`) |
| `SSN` | `123-45-6789`, `123 45 6789`, and the same shape with any **one** consistent separator — a dot (`123.45.6789`), any whitespace (NBSP included) or any Unicode dash (en/em dash, hyphen, minus) — with **any** digits, so ITINs (`912-70-1234`) and never-issued `666-…`/`000-…`/`…-00-…` values are redacted too; unseparated `123456789` only when it passes the SSA issuance rules (area not `000`/`666`/`9xx`, group not `00`, serial not `0000`) | an unseparated 9-digit run that could never have been issued — which is how routing numbers stay routing numbers; mixed separators (`123-45.6789`) |
| `PHONE` | US/NANP with `-`, `.` or space separators, optional parentheses, optional `+1`: `(415) 555-0132`, `+1(415) 555-0132`, `(415)`+tab/newline/NBSP+`555-0132`, `415-555-0132`, `212.555.0187`, `+1 646 555 0143` — also when glued to an extension (`415-555-0132x12` redacts the number). A parenthesized area code takes any digits; without parentheses, area and exchange must start `2`–`9` | an unformatted `4155550132`, a 7-digit local number, non-NANP international, an unparenthesized number whose area or exchange starts `0`/`1` (`123-456-7890`) |
| `CARD` | 13–19 digits with an optional space or hyphen between any two, **Luhn-valid** — every layout: `4111 1111 1111 1111`, `4111-1111-1111-1111`, unseparated, Amex `3782 822463 10005`, mixed separators, 8-8, 4-12, 6-13 and so on. The printed layouts (4-digit groups, Amex/Diners 4-6-5/4-6-4, unseparated) are also found after another digit group (`#2 4111 …`, a phone's last four) and before more digits (`4111 1111 1111 1111 12/27`, via a shorter retry) | runs that fail Luhn (deliberately — they are not card numbers); a card fused into a longer digit run with no separator; an irregular layout (8-8, 4-12, …) followed directly by more digits; other separators (dot, NBSP) |
| `IBAN` | grouped or compact, **mod-97-valid** — including when an uppercase word follows (`GB82 WEST … 32 ABCD`), by a mod-97 retry at the country's registered length (or any length for a country outside the ISO 13616 registry); groups may be separated by any whitespace | other bank identifiers (SWIFT/BIC, UK sort codes) |
| `ROUTING` | `Routing number: 021000021` — the English label is required | a bare routing number, which is not distinguishable from any other 9-digit run |
| `ACCOUNT` | `Account number: 000123456789` — 6 to 17 digits; the English label is required | a bare account number; a labelled one of 5 digits or fewer (indistinguishable from a year or amount elsewhere in the text) |
| `AMOUNT` | `$1,482.10` | other currencies |
| `DATE` | `01/14/2026` | every other date format |
| `NAME` | three demo names (`Ada Lovelace`, `Grace Hopper`, `Alan Turing`) | **every other name** — general name detection is not shipped |
| `MERCHANT` | five demo merchants (Whole Foods, Starbucks, Amazon, Walmart, Costco) | every other merchant |

The **Recognized** column is proved at the wire, not at the detector:
[`test/detector-completeness.test.ts`](../test/detector-completeness.test.ts) drives
each format through the real send path and fails if the value — or an
identifying fragment of it — reaches the network. The limits that are easiest to
widen by accident (`4155550132`, phone-shaped reference numbers, 9-digit runs
that are not issuable SSNs) are pinned as tests too, so quietly broadening a rule
turns them red. The floor is pinned the other way as well:
[`test/v022-recall-floor.test.ts`](../test/v022-recall-floor.test.ts) carries a
frozen copy of the v0.2.2 recognizers and fails if anything they redacted stops
being redacted, so a release cannot quietly narrow detection either.

