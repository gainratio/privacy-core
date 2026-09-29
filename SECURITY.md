# Security Policy

## Reporting a vulnerability

**Please report security issues privately — do not open a public issue.**

- Preferred: open a [GitHub private security advisory](https://github.com/hseshadr/privacy-core/security/advisories/new)
  (Security → *Report a vulnerability*).
- Or email **harish.seshadri@gmail.com** with `SECURITY` in the subject.

Useful things to include: what you found, how to reproduce it, the affected
file/API, and the impact you think it has. A proof-of-concept helps but isn't
required.

**What to expect:** an acknowledgement within a few days, and an honest assessment of
severity and fix timeline. This is a solo-maintained OSS reference project, not a funded
product — there's no bug-bounty payout, but credit in the fix/release notes is offered
unless you'd rather stay anonymous. Please give a reasonable window to ship a fix before
any public disclosure.

## Supported versions

Fixes land on the latest release on `main`. Older tagged releases are not patched —
upgrade to the current release.

## Security model (what's in scope)

privacy-core's whole design is **raw private text never crosses the wire**. The parts
worth probing:

- **The type-enforced Egress Guard.** Provider adapters accept *only* the branded
  `RedactedPayload` (`src/egress.ts`), whose sole legitimate constructor is
  `redactForEgress` (`src/redact.ts`). A raw `string` is not assignable — handing raw
  text to a provider is a **compile error**, not a runtime check. The brand factory
  (`mintPendingRedaction`) is deliberately not exported from the public barrel.
- **The reversible vault.** `Vault` (`src/vault.ts`) maps typed placeholders
  (`[CARD_1]`, `[NAME_2]`) back to real values **in memory only** (v0, by design — it
  clears on reload). Rehydration runs on-device after the reply; real values never
  leave the machine. Under a bound vault, an unresolvable placeholder fails closed
  (`UnresolvedPlaceholderError`) rather than leaving a lookalike token in place.
- **The audited escape hatch.** `unsafeBypass` is the only way to hand raw text to a
  provider, and it must emit an `AuditEntry`. A bypass that leaves no audit trail is
  a vulnerability.
- **The e2e wire proof.** A Playwright test intercepts the outbound request and
  asserts only placeholders cross the wire; that guarantee is the product.
- **No API key in the browser.** The library is env-agnostic — a host passes its
  own key in. The bundled Vite demo deliberately keeps `OPENROUTER_API_KEY`
  **server-side**: it is read only by a same-origin dev proxy (`vite.config.ts`)
  and injected into the outbound request, never `VITE_`-prefixed and so never
  embedded in the client bundle. Shipping a real key to the browser would be a
  bug; report it as one.

In-scope reports include: any way to construct or forge a `RedactedPayload` outside
`redactForEgress`; any path that puts raw (un-redacted) text on the wire; a bypass
that skips the audit sink; or vault contents escaping the local device.

**Known, documented limits (not vulnerabilities):** detection is deterministic
(regex + checksums + dictionaries) — recall is bounded, and the human-visible preview
is the backstop for anything the ruleset misses. The contextual NER tier that would
widen recall is deliberately deferred (see the roadmap in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#shipped-and-planned)).
