/**
 * Test-only fixtures, exposed via the `@gainratio/privacy-core/testing` subpath.
 * These are NOT part of the production barrel — keep synthetic data out of the
 * front door so consumers never ship a fixture by accident.
 */

/**
 * SYNTHETIC, INVENTED bank statement. Contains NO real PII.
 * - Cards 4242…4242, 4111…1111 and 5555…4444 are canonical processor test cards
 *   (Luhn-valid, not issued).
 * - ITIN 912-70-1234 and SSNs 345.67.8901 / 760-04-7660 are invented values.
 * - IBAN GB82 WEST… is the public mod-97 IBAN example from Wikipedia.
 * - SSN 123-45-6789 is a textbook placeholder.
 * - Routing 021000021 is a published ABA test routing number (JPMorgan Chase).
 * - `555-01xx` numbers are the NANP range reserved for fictional use.
 * - `example.com` and `.example` are RFC 2606 reserved names.
 *
 * The "Additional contacts" block exists so the BROWSER e2e exercises every
 * format the detector covers, not just the easy ones: an unseparated and a
 * space-separated SSN, a non-ASCII local part, an IDN domain, and hyphen-, dot-
 * and `+1`-formatted phones — plus the shapes the 0.3.0 security review found
 * leaking: a dashed ITIN (area `9xx`, which the SSA issuance rules reject), a
 * `+1` glued to a parenthesized area code, and a card followed by its expiry
 * (the greedy match fails Luhn and must be retried shorter); and from the
 * re-review, a phone glued to an extension, a dot-separated SSN, a card after
 * another digit group, and an SSN right after a reference number (whose tail
 * leaked when overlapping spans were dropped instead of merged). Node and Chromium
 * do not share an execution path for Unicode regex semantics or source
 * decoding, so these have to live in the fixture a real browser drives — a unit
 * test cannot vouch for them.
 *
 * Each value appears exactly ONCE: a standalone second copy of an already-vaulted
 * value is what the residual guard fails closed on.
 */
export const SYNTHETIC_STATEMENT = `MONTHLY STATEMENT — FIRST INVENTED BANK

Account holder: Ada Lovelace
Email: ada.lovelace@example.com
Phone: (415) 555-0132
SSN on file: 123-45-6789

Additional contacts on this account:
  Joint holder SSN 223456789, mobile 415-555-0148
  Beneficiary SSN 234 56 7890, daytime line 212.555.0187
  Statements to josé.álvarez@example.com and kontakt@münchen-bank.example
  Branch callback: +1 646 555 0143
  Tax ID: ITIN 912-70-1234, fax +1(415) 555-0199
  Backup card 4111 1111 1111 1111 12/27
  Callback 415-555-0177x12; alt SSN 345.67.8901; ref #2 5555 5555 5555 4444
  Case 3852631216 760-04-7660

Account number: 000123456789
Routing number: 021000021
Linked IBAN: GB82 WEST 1234 5698 7654 32
Card on file: 4242 4242 4242 4242

Transactions:
  01/05/2026  Whole Foods            $1,482.10
  01/09/2026  Starbucks                 $7.45
  01/14/2026  Amazon                  $329.00

Please review the charge to Whole Foods.`;
