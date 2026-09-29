# Shared Dagger Lego adoption

## TL;DR

Privacy Core pins the shared Foundation module to
`9d491851fc5c65ad4a388ed2dd7bb4def4e1f007`. The canonical Dagger check binds the
caller snapshot to its exact public Git commit and completes the shared guard before
any product or security gate runs.

The npm release path remains local. Central CI has no npm or TypeScript package
candidate/publisher module at this commit, so replacing Privacy Core's source-free npm
OIDC bridge would weaken or redesign an already proven authority boundary.

## Run the protected proof

From a clean clone of a public commit:

```bash
corepack enable pnpm
pnpm install --frozen-lockfile
dagger develop
DAGGER_NO_NAG=1 dagger call ci \
  --commit-sha="$(git rev-parse HEAD)"
```

The proof fails closed when the working source differs from that public commit. Pushes,
pull requests, manual runs, and the Monday security sweep all enter through the same
exact-`github.sha` Dagger job. Repository protection requires the resulting `Dagger`
check on `main`.

## Ownership boundary

| Owner | Responsibility |
| --- | --- |
| Central Foundation at the exact pin | Public source/history binding plus snapshot, history, and workflow guard |
| Privacy Core Dagger module | TypeScript quality, dependency audit, browser privacy proof, candidate construction, and package identity |
| Local release workflows | Exact-tag eligibility, one-day source-free candidate transfer, npm trusted publishing through GitHub OIDC, and provenance |

`release-candidate.yml` and `publish.yml` deliberately remain local and unchanged. The
publisher receives only the closed candidate directory and ephemeral GitHub OIDC
request credentials; it does not check out or rebuild source. A future central npm Lego
must preserve that exact source-free contract, package inventory checks, checksum,
trusted-publisher identity, and `npm publish --provenance` boundary before migration.

## Audit snapshot

On 2026-08-29, `main` required the strict `Dagger` check from the GitHub Actions app,
enforced protection for administrators, and used read-only default workflow tokens.
There were no repository rulesets or deployment environments. This migration changes
no version, npm dependency, tag, registry, secret, environment, package candidate, or
publisher behavior.
