# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **The README is rewritten in plain English.** It now says who the library is
  for, what it does, one real example run against the published 0.3.0 package
  (including the name it does not catch), honest limits and alternatives. The
  deep material moved, not deleted: the format table to `docs/DETECTION.md`, the
  API, receipts and settings to `docs/API.md`, and the security model, proof
  table and roadmap to `docs/ARCHITECTURE.md`. New `docs/GETTING_STARTED.md`
  takes a developer from clone to a first change. The package description
  matches the README's first line, and `test/readme.contract.test.ts` pins the
  new sections, facts and a banned-jargon list.

- **The release candidate is back to the fleet's shell-free shape: checkout,
  Dagger, upload.** The central `hseshadr/ci` fleet policy forbids `run:` steps
  and reported `shell-step` and `candidate-order` on `release-candidate.yml`.
  The dispatched tag still never reaches script text. It enters the pinned
  `dagger/dagger-for-github` step only as the `TAG` environment variable, and
  `args` hold only double-quoted variables (`--tag="$TAG"
  --commit-sha="$GITHUB_SHA"`), so bash expands the tag as one inert word. The
  separate `vX.Y.Z` shell step is gone, because Dagger's `_require_tag` already
  refuses anything else. `test/dagger-workflow.test.ts` now expands the real
  `args` in bash with hostile tags and asserts that each one arrives as a single
  literal argument and runs nothing. `publish.yml` is unchanged: its lineage
  and provenance steps are real controls that fleet policy cannot express yet
  (hseshadr/ci#49).
- **The README follows the portfolio template.** Its first screen is written for
  a non-specialist: a plain tagline, a hero that is the real output of a
  15-line example run against the published 0.3.0 package, an "At a glance"
  list (including exactly what stays on the device and what leaves it) and a
  "Try it in 60 seconds" section. The deeper material (recognized formats,
  receipts, compile-time guard, public API) moves below the fold unchanged,
  alongside new "Why this and not X", security, evidence and configuration
  sections. `package.json` `description` is now the same tagline, still stating
  that names and other details are not caught; the published 0.3.0 keeps its
  old description. A Vitest README contract test (`test/readme.contract.test.ts`,
  inside `pnpm gate`) pins the first-screen structure, the tagline/description
  equality, the architecture-map link, the Beta status at the package version,
  and every relative link.
- **The 512 KiB hostile-input timing guard now catches a slowdown anywhere in
  `detect()`, not only in the IBAN retry.** It was one relative bound (IBAN
  shapes within 7x a card-shaped workload), so a slowdown in the shared scan or
  merge code slowed the reference too and passed. It now times IBAN, card and
  email worst shapes in a plain Node child, outside coverage instrumentation,
  and asserts both an absolute ceiling (each shape under 1.5 s, measured
  100-250 ms) and a tighter relative bound (IBAN shapes under 3x the card
  workload, measured at most 1.4x). A quadratic merge (`[...kept].pop()` per
  span) passed the old guard and fails the new one (`a.b@c.` 3.8 s); the
  pre-fix per-group IBAN retry measured 3.9-5.4x, which a 4x bound would
  sometimes miss. Test-only; no change to the published package.

## [0.3.0] — 2026-09-23

### Fixed

- **The detector no longer leaks three ordinary formats of the PII it advertises.**
  Each was a real leak, reproduced as a failing test that drove the value through
  the actual send path before any fix landed.
  - **Email now matches every script.** JavaScript's `\w` and `\b` are ASCII-only,
    so `josé.álvarez@example.com` matched only its ASCII tail and was redacted as
    `josé.á[EMAIL_1]` — a silent PARTIAL leak that a whole-value absence check
    would have scored a pass. The recognizer now uses Unicode property escapes
    under the `u` flag on both sides of the `@`, so IDN domains match too. Edges
    are asserted explicitly (a lookbehind, and a trailing alphanumeric) since `\b`
    could not do the job; every quantifier stays un-nested, so the pattern is
    linear and a ReDoS test pins that.
  - **SSN now matches `123 45 6789`, unseparated `123456789`, and the same
    shape with any one consistent separator** — a dot, any whitespace (NBSP
    included) or any Unicode dash (en/em dash, hyphen, minus) — not only the
    dashed form. Only the unseparated form is gated on the SSA issuance rules
    (new `ssnValid`: area not `000`/`666`/`9xx`, group not `00`, serial not
    `0000`), which is what makes a bare 9-digit run safe to recognize — group
    `00` is never issued, so ABA routing numbers are excluded by construction.
    Separated values are redacted whatever their digits, exactly as the dashed
    form was in 0.2.2.
  - **Phone now matches the NANP set**, not only `(415) 555-0132`: `-`, `.` or
    space separators, optional parentheses, optional `+1` (also glued to the
    parenthesis: `+1(415) 555-0132`). Without parentheses, area and exchange must
    start `2-9`; a parenthesized area code takes any digits and may be followed
    by any single whitespace character, as in 0.2.2. A number glued to its
    extension (`415-555-0132x12`) is redacted: the pattern ends at "no further
    digit" rather than at a word boundary. An unformatted 10-digit run is still
    deliberately NOT matched.
  - **`Account number:` now takes 6–17 digits** (was 9–12), so a labelled
    13–17-digit account number no longer leaks. Five digits or fewer stay out:
    they collide with years and amounts elsewhere in the text, which the
    residual guard would then refuse to send.
- **A card preceded by another digit group is no longer missed whole.**
  `(415) 555-0132 4111 1111 1111 1111`, `SSN 123-45-6789 4111 1111 1111 1111`
  and `#2 4111 1111 1111 1111` leaked the entire card 80–90% of the time (and
  did in 0.2.2): the old `(?:\d[ -]?){13,19}` recognizer took any 13–19 digits
  with a separator anywhere, so the neighbour's digits were glued on, the result
  failed Luhn, and scanning resumed after the whole run. CARD now has two
  Luhn-gated rules. A print-layout grammar — 13–19 unseparated digits; 4-digit
  groups with one consistent space or hyphen (a short last group for 13–15
  digits, one trailing 1–3 digit group for 17–19); Amex/Diners 4-6-5 / 4-6-4 —
  is tried at EVERY start instead of resuming after a rejected candidate, so a
  neighbour can no longer hide the card. Beside it, v0.2.2's loose
  `(?:\d[ -]?){13,19}` rule (ending on a digit, so it no longer swallows the
  space after a card) still runs the v0.2.2 way, resuming after each match, so
  every layout v0.2.2 redacted — mixed separators, 8-8, 4-4-8, 4-12, 6-10,
  6-13, 4-3-3-3, 4-4-4-6/7 — is still redacted. (A second re-review found the
  grammar alone had dropped those ten layouts from 100% to 0%; restoring the
  loose rule is safe now that overlapping spans merge, because its chance
  Luhn-valid glue can only widen what is redacted.)
- **A checksum-rejected match is now retried shorter instead of leaking whole.**
  The regex engine reports only the longest match at a position, so a valid card
  or IBAN followed by more digits or an uppercase word
  (`4111 1111 1111 1111 12/27`, `4111 1111 1111 1111 123 exp…`,
  `GB82 WEST 1234 5698 7654 32 ABCD`) was matched too long, failed Luhn/mod-97,
  and went out verbatim. This predates 0.3.0. After a rejection, `detect()` now
  retries shorter candidates from the same start, longest first; a candidate
  must be a complete match of the rule's own pattern and end on a word boundary
  in the full text, so a card is never carved out of a longer digit run. Each
  rule names its candidates: every word-closing prefix of a print-layout card
  (≤ 23 chars), and for an IBAN only the word-closing prefixes that already
  pass mod-97 — at the country's registered ISO 13616 length (89 countries in
  `IBAN_LENGTHS`), or at 15+ characters for a country outside the registry
  (bank-issued codes such as `MA`, `NC`, `PF`) — found in one pass that folds
  the remainder as it goes. Any whitespace the pattern accepts counts as a
  separator, so tab- and NBSP-grouped IBANs are retried at the right length.
  (A final review of the first table-only version found both gaps: an
  unregistered country followed by text leaked ~4% of cases, a tab/NBSP-grouped
  IBAN followed by a word ~95%; both are now 0 of 1,860.) Detection stays
  linear: a 64 KiB adversarial test, and a 512 KiB IBAN-shaped one that an
  earlier per-group retry had made ~25x slower (1.2–1.6 s, now ~155–245 ms),
  pin it. `ibanValid` now folds mod-97 without building an expanded digit
  string — same result, a fraction of the work.
- **Overlapping spans are merged into their union instead of dropped.** When
  two rules matched overlapping text, `detect()` kept the earlier/longer span
  and DROPPED the other, uncovering whatever the dropped span held beyond the
  overlap. The first 0.3.0 candidate made this an active leak (see *Security*);
  it also lost `(747)\t712-1349` in `$1(747)\t712-1349` and the card in
  `(144).076-2191 4111-1111-1111-1111`. The earlier span now extends to the later
  one's end — its type is kept, its value becomes the union's exact text, and
  the vault round-trips it — so an overlap can only widen what is redacted.

### Security

- **Email detection is no longer quadratic.** v0.2.2's
  `\b[\w.+-]+@[\w-]+\.[\w.-]+\b` retried its unbounded local part from every
  start of a run with no `@`, so a `1234-1234-…` run took ~0.6 s at 32k
  characters, ~2.5 s at 64k and ~10 s at 131k (quadrupling per doubling;
  minutes at the 512 KiB input cap) on the browser thread. The 0.3.0 email
  recognizer's lookbehind stops a match starting mid-run, and all of 0.3.0's
  `detect()` takes ~90 ms on the same 131k input.
- **The 0.3.0 widening no longer narrows anything 0.2.2 redacted.** A
  pre-release security review ran the v0.2.2 and 0.3.0 `src/detect` trees side
  by side and found the first 0.3.0 candidate had quietly STOPPED redacting
  values 0.2.2 caught. Both are fixed before release, each with a failing
  regression test first:
  - the `ssnValid` issuance gate had been applied to the dashed and spaced SSN
    forms too, so ITINs (`912-70-1234`, `987-65-4321` — real taxpayer IDs) and
    never-issued `666-12-3456`, `000-…`, `123-00-4567` values leaked. The gate
    now applies only to the unseparated 9-digit form;
  - a re-review of that fix found the new checksum retry had introduced a
    leak of its own: it carved a Luhn-valid "card" out of a reference number
    plus the next SSN's area code (`3852631216 760-04-7660`,
    `896 38 9043 725-71-9450`), and the overlap pass then dropped the SSN, so
    `-04-7660` went out bare — 9–17% of phone+SSN, reference+SSN and SSN+SSN
    lines, against 0% in 0.2.2. Fixed by the union merge and the card grammar
    above (0% on the same measurement);
  - the NANP phone pattern had dropped `+1(415) 555-0132` and `1(415) 555-0132`
    (country code glued to the parenthesis), `(415)` followed by NBSP, tab or
    newline (0.2.2 allowed `\s?` there), and parenthesized numbers whose area or
    exchange starts `0`/`1` (`(123) 456-7890`, `(415) 155-0132`). All match
    again, and every shape the widened pattern gained is kept.

  A new recall-floor test (`test/v022-recall-floor.test.ts`) now makes this
  class of regression fail the gate: it carries a frozen, verbatim copy of the
  v0.2.2 PHONE/SSN/EMAIL/CARD/IBAN recognizers and checksums, asserts every value
  v0.2.2 redacted in its own test corpus is still redacted, and sweeps a
  generated corpus asserting every character v0.2.2 matched is still covered —
  one identifier per line, and a seeded corpus of 20,000 lines carrying two or
  three side by side (phone next to SSN, reference number before a card), which
  is where the re-review's leak lived; that corpus fails on the first fix.
- **Release dispatch no longer interpolates the `tag` input into shell.**
  `release-candidate.yml` passed `${{ inputs.tag }}` to
  `dagger/dagger-for-github`'s `args`, which that action templates into a bash
  script — a tag containing `'` ran arbitrary shell in the job that produces the
  release artifact, which the publisher only checks against a `SHA256SUMS` from
  the same artifact. The tag now reaches shell only as `$TAG` via `env:`, a first
  step rejects anything but `^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`,
  the Dagger `release_candidate` function re-checks it, and the action is used
  only to put the Dagger CLI on `PATH` (both `release-candidate.yml` and
  `publish.yml` call `dagger` from their own `run:` step with quoted values). A
  workflow test now fails if any `inputs.*` or `github.event` expression reaches
  a `run:` script or an action's shell-templated `args`/`call`/`shell`/`check`.
- **The Dagger npm publisher can now actually produce provenance.** It ran
  `npm publish --provenance` in a container whose only environment was the OIDC
  request URL/token, so npm 11.13 (bundled with the pinned `node:24.16.0` image)
  could not detect GitHub Actions and would have failed with
  `EUSAGE: Automatic provenance generation not supported for provider: null` —
  and skipped the trusted-publishing token exchange. `publish.yml` now records
  the run's GitHub Actions context (`GITHUB_WORKFLOW_REF`, `GITHUB_REPOSITORY`,
  `GITHUB_SHA`, `GITHUB_RUN_ID`, `GITHUB_RUN_ATTEMPT`, `GITHUB_SERVER_URL`,
  `GITHUB_EVENT_NAME`, `GITHUB_REF`, `GITHUB_REPOSITORY_ID`,
  `GITHUB_REPOSITORY_OWNER_ID`, `GITHUB_WORKFLOW`, `RUNNER_ENVIRONMENT`) to a file
  outside the candidate, and the Dagger `publish` function validates every value
  — this repository, `github.com`, a GitHub-hosted runner, and a workflow ref of
  exactly `.github/workflows/publish.yml` (the file npm trusted publishing is
  bound to, whose name is unchanged) — before setting it, plus
  `GITHUB_ACTIONS=true`/`CI=true`, in the publisher container. The canonical
  Dagger gate now runs `scripts/provenance-probe.mts` in exactly that container:
  a real `npm publish --provenance` of a throwaway package against a loopback
  stub, which must get past provider detection and start provenance generation
  (sigstore requests its OIDC token), while a control run with the GitHub
  variables stripped must still fail with `provider: null`. (`--dry-run` could
  not prove this: npm 11 returns before provenance on a dry run.) It does not
  exercise a real OIDC exchange or Sigstore signing — only a GitHub run can.
  The publisher also hands npm the archive as `./<name>.tgz`, so the argument
  can never be read as an `owner/repo` GitHub shorthand.
- **The publisher now binds the candidate to `main`.** `publish.yml` only
  checked `workflow_run.head_branch == default_branch`, which a dispatch on a
  TAG named `main` also satisfies. Before touching the artifact it now verifies,
  through the GitHub API, that the triggering run is a successful
  `workflow_dispatch` of `release-candidate.yml` in this repository for exactly
  the candidate's commit, and that this commit is reachable from the
  default-branch commit the publish runs on; the archive is that run's own
  artifact for that commit. The Dagger publisher code is loaded from that
  default-branch commit (`$GITHUB_SHA`), not from the candidate's sha.
- **The pnpm supply-chain cooldown is declared again.** `minimumReleaseAge: 1440`
  was removed in #32 ("replace the artificial 24-hour registry wait … with an
  explicit reviewed build allowlist") and a test asserted its absence — but pnpm
  11.5.0 defaults to 1440 anyway, so the cooldown never actually stopped
  applying; only the repository stopped stating it. It is restored explicitly
  (a frozen install of the pinned toolchain passes with it) and
  `test/registry-maturity.test.ts` now requires it, with no exclusion list and no
  non-strict escape hatch.

### Changed

- **Egress receipts now carry `detector_version: "2"`.** `DETECTOR_VERSION` is
  bumped from `"1"` because the detection ruleset changed (the Unicode email,
  spaced/unseparated SSN and NANP phone recognizers under *Fixed*, and the SSN
  and phone narrowings under *Security* fixed before release), so a 0.3.0
  receipt can be told apart from one sealed by 0.2.x. This is a wire-visible
  change: a verifier that compares `detector_version` against an allow-list must
  accept `"2"`. Receipts sealed with a caller-pinned `detectorVersion` are
  unaffected. A new test pins each detector version to a fingerprint of the
  ruleset (every rule's type, pattern, flags and accept-gate in priority order,
  plus the dictionaries), so a ruleset change without a version bump now fails
  the gate.
- **Truth-in-labeling: the package is described as what it is — a
  structured-identifier redaction boundary.** The npm `description` now names
  the detected categories (cards, IBANs, SSNs, emails, US phones, labeled
  account/routing numbers) and says names and free-text PII are not detected;
  the `anonymization` keyword is removed (the README already says redaction does
  not make data anonymous). The README headline no longer implies general name
  detection, notes that the demo's *Grace Hopper* is one of 3 built-in demo
  names, and "The model never sees you" is now "The model never sees what the
  detector catches". Docs only — no behavior or wire change.

- **The README front door is now one sentence, one proof, one command.** The
  first screenful states what the library does, shows the real before/after of
  the example that follows, and gives the single command that runs it. A new
  "Use it in your own repo" section replaces the old walkthrough with a 23-line
  example that was run against `@edgeproc/privacy-core@0.2.2` installed from
  npm in an empty directory — the pasted output is that run's stdout, byte for
  byte. Everything else (the recognized-formats table, the limits, receipts,
  the developer sections) moved below the fold unchanged.
- **The browser e2e now proves the widened formats in real Chromium.**
  `SYNTHETIC_STATEMENT` carries an "Additional contacts" block containing every
  newly-covered format — including a dashed ITIN, `+1(415) 555-0199`, a card
  followed by its expiry, a phone glued to an extension, a dot-separated SSN, a
  card after another digit group and an SSN right after a reference number, the
  shapes the security reviews found leaking — and
  the Playwright suite asserts each raw value *and its
  identifying fragments* are absent from both the intercepted request body and
  the rendered wire pane, requires the placeholders those recognizers must mint
  (non-vacuity), and fails on any console error or warning during the flow. A
  Node test with a spied `fetch` cannot vouch for `u`-flag regex semantics under
  a different engine; this can. The suite also asserts the demo actually mounted,
  so an unrelated dev server squatting port 5173 fails with a named error instead
  of a bare "element(s) not found".
- **`RULES` order is now the documented tie-break** for the TYPE of spans of equal
  length at the same offset (`Array.prototype.sort` has been stable since ES2019).
  The label-gated `ROUTING`/`ACCOUNT` rules are listed before `SSN`, so
  `Account number: 100200300` stays an `ACCOUNT` even though those digits are also
  a structurally valid SSN.
- **The README now publishes a per-type coverage table** ("What it recognizes,
  exactly") stating what each recognizer accepts *and* what it does not, and the
  QUICKSTART, ARCHITECTURE TL;DR and `detect()` docstring point at it instead of
  implying the detector finds all PII.
- **The architecture diagram is now an inline mermaid fence**, and the d2 source
  plus its committed SVG are deleted. d2 emitted a ~4:1 letterbox SVG that GitHub
  scaled to about 160px tall in its ~1000px column, which made every label
  unreadable. Mermaid renders legibly, has no generated artifact that can go stale
  against the code, and diffs in review. Weaker layout control is the accepted
  trade. The diagrams directory is gone; there is no render step to run.

- **Runtime dependency `@edgeproc/avow` moves from `^0.1.1` to `^0.4.1`** (0.2.2
  shipped `^0.1.0`). This is the minor-version reason for this release: `^0.1.x` could
  never resolve a 0.4 envelope. What this package calls is unchanged —
  `signPayload`, `contentHash` (re-exported), and the `SignedReceipt` shape produce
  the same canonical bytes, hashes, and signatures, so receipts sealed by 0.2.x still
  verify and new receipts verify under older verifiers. What changes is what a
  verifier sees when it rejects a receipt:
  - a tampered payload now throws `PayloadHashMismatch` with code
    `avow.payload_hash_mismatch`. Before, the class was `ReplayMismatch` and the
    code was `avow.replay_mismatch`. `ReplayMismatch` remains as a deprecated alias
    of the new class, so `instanceof` checks keep working, but code matches on the
    old string no longer do;
  - a wrong signer throws `SignerMismatch` (`avow.signer_mismatch`), and bad
    signature bytes throw `SignatureBytesInvalid` (`avow.signature_invalid`). Both
    still extend `SignatureInvalid`;
  - the pinned public key is compared case-insensitively, so the same key written in
    upper- and lower-case hex no longer reads as a signer mismatch.

  The receipt tests assert each rejection by its own subclass and code, and
  `test/receipt-compat.test.ts` pins two receipts sealed by the published
  `@edgeproc/privacy-core@0.2.2` (on `@edgeproc/avow@0.1.0`) with a fixed seed:
  they verify under `^0.4.1`, and re-sealing the same decision today produces the
  byte-identical payload hash and signature.

## [0.2.2] — 2026-07-25

Hardening release, and the first cut published with npm build **provenance** — a
signed, public transparency-log attestation linking the package to this repo and
its publish workflow. No public API breaks.

### Security

- **IBAN detection is no longer vulnerable to catastrophic backtracking.** The
  recognizer nested a bounded quantifier inside an unbounded one
  (`(?:\s?[A-Z0-9]{2,4})+`); a crafted near-IBAN froze the browser thread for
  ~0.5s (exponential in input length), defeating the "synchronous detection
  bounded on the browser thread" guarantee. Replaced with a linear,
  whitespace-tolerant pattern, guarded by a performance regression test.
- Dev-only `postcss` forced to the patched line (`>=8.5.18`) for
  GHSA-r28c-9q8g-f849 (source-map path traversal). It ships only in build
  tooling, never in `dist`; `pnpm audit` is clean including dev dependencies.

### Fixed

- **Silent failures now surface as typed, fail-closed errors.** `makeProvider`
  no longer returns the offline echo when a production API key is merely missing:
  the offline provider is opt-in via `allowOffline: true`, and a missing key
  throws the new `MissingApiKeyError`. `OpenRouterProvider` throws the new
  `MalformedProviderResponseError` instead of returning `""` when a reply lacks a
  string `choices[0].message.content`, and enforces the response byte cap BEFORE
  buffering a non-streamed body (a missing/untrusted `content-length` fails closed
  rather than buffering unbounded).
- **Governed egress now awaits the `onReceipt` sink**, so a send does not complete
  until the decision receipt has been durably handled (`onReceipt` may return a
  promise).
- Governed egress records a signed denial even when a plain-JavaScript caller
  supplies a malformed payload (`null`, a non-string text field, or a hostile
  getter), preserving the fail-closed error and receipt invariant.
- Redaction rejects inputs over 512 KiB of UTF-8 before detector, vault, or
  audit work, with an exported typed error and documented limit.
- OpenRouter requests have a 30-second default deadline and 1 MiB streamed
  response cap, with optional configuration overrides and typed fail-closed
  timeout/overflow errors.

### Changed

- All typed errors now share an exported `PrivacyCoreError` base, so a consumer
  can catch every boundary failure with one `instanceof`.
- `AuditEntry` is now a discriminated union on `kind` (`redact`/`approve` carry
  `placeholders`; `unsafe-bypass` carries `reason`), and its member types are
  exported. A minted `PendingRedaction`'s `placeholders` array is deep-frozen.
- The runnable demo now demonstrates both advertised guarantees directly: a
  "Sign egress receipts" toggle seals each allow/deny as a signed receipt, and a
  "Try to send without approval" action shows the fail-closed refusal. The
  Playwright e2e suite drives both.
- Remaining internal vocabulary removed from shipped and public-facing surfaces
  (source doc comments, tests, and `CLAUDE.md`).

## [0.2.1] — 2026-07-21

First release shipped through the token-free OIDC release rail: a `v*` tag push
runs the reusable `hseshadr/ci` publish workflow, which authenticates to npm as
a registered Trusted Publisher — no npm token exists anywhere in this repo.
No library code changes.

### Added

- Tag-triggered npm publish caller (`.github/workflows/publish.yml`) delegating
  to the reusable `hseshadr/ci` ts-publish workflow via OIDC Trusted Publishing.
- `repository.url` in `package.json` (required for npm OIDC trusted publishing).

### Changed

- README rewritten around a concrete scenario a first-time reader immediately
  gets; docs scrubbed of internal vocabulary.
- The receipt-sealing claim in the docs is scoped to its opt-in reality.

### Security

- All GitHub Actions pinned to full commit SHAs and enforced by the test suite;
  the publish caller pins the `hseshadr/ci` reusable workflow to an immutable
  SHA (ci-v2.0.3), closing the transitive pinning hole.
- pnpm supply-chain cooldown (minimum release age) restored and guarded with a
  test against silent exemptions.
- Signature and residual-leak tests strengthened to exercise the properties
  they name.

## [0.2.0] — 2026-07-20

A breaking release (the egress API changed, see below). Also drops the local
`link:` dependency on `@edgeproc/avow` in favour of the published
`@edgeproc/avow@^0.1.0` from npm, and publishes this package publicly as
`@edgeproc/privacy-core`.

### Changed — BREAKING

- **Approval is now an explicit step, never a side effect.** `redactForEgress`
  returns a `PendingRedaction` (a review proposal — not sendable) instead of a
  `RedactedPayload`; the new `approve(pending, audit?)` step is the only way to
  mint the sendable capability, and it emits an `"approve"` audit entry. A
  zero-detection result no longer auto-approves: "the detector found nothing"
  is not "a reviewer approved this". Migration:
  `provider.complete(await redactForEgress(raw, vault))` →
  `provider.complete(approve(await redactForEgress(raw, vault)))`.
  `approve()` rejects hand-built pendings with the typed `ForgedPayloadError`.
- **The capability is now unforgeable at runtime, not just in the type
  system.** Every approved payload is registered by identity in a
  module-private `WeakSet`; every provider adapter calls the new
  `assertApproved()` before doing anything, so a structurally identical
  hand-built payload (or a spread-clone of a real one) is rejected with the
  typed `UnapprovedPayloadError` before any network call. Payloads and
  pendings are frozen, closing the mutate-after-approval hole. Custom
  `LlmProvider` implementations should call `assertApproved()` first —
  it is exported for exactly that.
- **Reversibility failures now fail closed with typed errors.**
  `redactForEgress` throws `PlaceholderCollisionError` when the input already
  contains placeholder-shaped text (`[CARD_1]`) — previously such text passed
  through and `rehydrate` would silently substitute vault values into text
  that never contained them. `rehydrate` accepts the payload's `vaultRef` as
  an optional third argument and throws `VaultMismatchError` when handed the
  wrong vault instead of silently restoring wrong/missing values (the demo
  passes it).

### Added

- `LICENSE` file (MIT — the license the package always claimed), `SECURITY.md`,
  `CONTRIBUTING.md`, and `CLAUDE.md` (agent doc with scarred quality gates and
  the §8 not-applicable-yet declaration).
- `docs/ARCHITECTURE.md` + `docs/QUICKSTART.md` with a committed d2 diagram
  (`docs/diagrams/privacy-loop.d2` + rendered SVG) of the
  detect → vault → egress-guard → rehydrate loop.
- Coverage thresholds (90 lines / 90 functions / 85 branches) enforced via
  `pnpm test`, plus the tests that took branch coverage from 79% to 100%
  (checksum bounds, unknown-token rehydrate, provider error paths, detector
  overlap tie-break).
- Biome `noExcessiveCognitiveComplexity` (max 15) as the TS complexity gate.
- CI: gitleaks full-history job, weekly `pnpm audit --audit-level moderate`
  security-audit workflow, and grouped weekly dependabot updates.

### Changed

- `ci.yml` now literally runs `pnpm gate` (the exact local command) instead of
  five hand-copied steps; `pnpm/action-setup` v4 → v6 (version read from
  `packageManager`).

## [0.1.0] — 2026-05-29

Initial graduation from the proven spike: deterministic detection spine +
reversible in-memory vault + type-enforced Egress Guard + redact→rehydrate loop
+ demo.

### Added

- **Deterministic detection spine** (`detect`) — ported Presidio-style regex +
  checksum recognizers (Luhn, IBAN mod-97, SSN, email, phone, amounts, dates)
  plus finance/name dictionaries.
- **Reversible in-memory vault** (`Vault`) — stable typed placeholders
  (`[CARD_1]`, `[NAME_2]`), same value → same token.
- **Type-enforced Egress Guard** — branded `RedactedPayload`, the `LlmProvider`
  interface that accepts only that brand, and the audited `unsafeBypass` escape
  hatch. Handing raw text to a provider is a compile error.
- **Reversible loop** — `redactForEgress` (the only legitimate payload
  constructor) and `rehydrate` (local restore).
- **Providers** — `NoLLMProvider` (offline echo, runs cold), `OpenRouterProvider`
  (OpenAI-compatible), and `makeProvider` factory.
- **Runnable demo** (`examples/demo`) consuming only the public API, with the
  redact → preview → send → rehydrate wow loop and a `docs/wow.png` proof.
- **Tests** — Vitest unit suite + a Playwright headless-chromium e2e that asserts
  only placeholders cross the wire.
