"""Privacy Core's complete quality, security, and release-candidate graph."""

from __future__ import annotations

import json
import re
from typing import Final, Self

import dagger
from dagger import check, dag, field, function, object_type

NODE_IMAGE: Final = (
    "node:24.16.0-bookworm-slim@sha256:"
    "2c87ef9bd3c6a3bd4b472b4bec2ce9d16354b0c574f736c476489d09f560a203"
)
ACTIONLINT_IMAGE: Final = (
    "rhysd/actionlint:1.7.10@sha256:"
    "ef8299f97635c4c30e2298f48f30763ab782a4ad2c95b744649439a039421e36"
)
GITLEAKS_IMAGE: Final = (
    "ghcr.io/gitleaks/gitleaks:v8.29.1@sha256:"
    "aa036a2f4bdfe3cc3c55fa4326308efabb4a6be498c883c864fd1d0d5585438a"
)
# The run's own `github.repository` must be one of exactly these two: today's
# user-owned repository, and the same repository after the gainratio org move.
# Exact membership only, never an owner wildcard. Defaults stay today's value.
ALLOWED_REPOSITORIES: Final = ("hseshadr/privacy-core", "gainratio/privacy-core")
REPOSITORY: Final = ALLOWED_REPOSITORIES[0]
REPOSITORY_URL: Final = f"https://github.com/{REPOSITORY}.git"
PNPM_VERSION: Final = "11.5.0"
SHA_LENGTH: Final = 40
RELEASE_TAG: Final = re.compile(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
DIGITS: Final = re.compile(r"[0-9]+")
BRANCH_REF: Final = r"refs/heads/[A-Za-z0-9._/-]+"
# The GitHub Actions context npm needs inside the publisher container. npm
# 11.13.0 (bundled with NODE_IMAGE) detects GitHub Actions through ci-info's
# GITHUB_ACTIONS, only then attempts the OIDC trusted-publishing exchange, and
# writes these values into the SLSA provenance statement
# (libnpmpublish/lib/provenance.js); the registry checks them against the
# Sigstore certificate. A container carrying only the OIDC request variables
# fails with `EUSAGE: Automatic provenance generation not supported for
# provider: null`. Each value is validated, because this is the only
# caller-supplied text that reaches the publisher.
PROVENANCE_CONTEXT: Final[dict[str, re.Pattern[str]]] = {
    "GITHUB_EVENT_NAME": re.compile(r"workflow_run"),
    "GITHUB_REF": re.compile(BRANCH_REF),
    "GITHUB_REPOSITORY": re.compile("|".join(map(re.escape, ALLOWED_REPOSITORIES))),
    "GITHUB_REPOSITORY_ID": DIGITS,
    "GITHUB_REPOSITORY_OWNER_ID": DIGITS,
    "GITHUB_RUN_ATTEMPT": DIGITS,
    "GITHUB_RUN_ID": DIGITS,
    "GITHUB_SERVER_URL": re.compile(r"https://github\.com"),
    "GITHUB_SHA": re.compile(r"[0-9a-f]{40}"),
    "GITHUB_WORKFLOW": re.compile(r"[ -~]+"),
    # npm trusted publishing is bound to this exact workflow file.
    "GITHUB_WORKFLOW_REF": re.compile(
        "(?:"
        + "|".join(map(re.escape, ALLOWED_REPOSITORIES))
        + ")"
        + re.escape("/.github/workflows/publish.yml@")
        + BRANCH_REF
    ),
    "RUNNER_ENVIRONMENT": re.compile(r"github-hosted"),
}
ARCHIVE_NAME: Final = re.compile(
    r"^gainratio-privacy-core-(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.tgz$"
)
CHECKSUM_LINE: Final = re.compile(r"^[0-9a-f]{64}  (?P<archive>[^\n]+)\n$")
SOURCE_EXCLUDES: Final = [
    ".git",
    ".dagger/.mypy_cache",
    ".dagger/.pytest_cache",
    ".dagger/.ruff_cache",
    ".dagger/.venv",
    ".dagger/sdk",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "**/__pycache__",
    "node_modules",
    "**/node_modules",
    "coverage",
    "dist",
    "playwright-report",
    "test-results",
]
INSTALL_COMMAND: Final = ["pnpm", "install", "--frozen-lockfile"]
PLAYWRIGHT_INSTALL: Final = [
    "pnpm",
    "exec",
    "playwright",
    "install",
    "--with-deps",
    "chromium",
]
GITLEAKS_SNAPSHOT: Final = [
    "gitleaks",
    "detect",
    "--source",
    "/snapshot",
    "--no-git",
    "--redact",
    "--no-banner",
]
GITLEAKS_HISTORY: Final = [
    "gitleaks",
    "detect",
    "--source",
    "/repo",
    "--log-opts=--all",
    "--redact",
    "--no-banner",
]

# A synthetic, valid publisher context for the provenance probe. The probe runs
# the real npm from NODE_IMAGE against a loopback stub, so these values never
# reach a registry; they only need to pass the same validation as a real run.
PROBE_PORT: Final = 47291
PROBE_SCRIPT: Final = "scripts/provenance-probe.mts"
PROBE_CONTEXT: Final = {
    "GITHUB_EVENT_NAME": "workflow_run",
    "GITHUB_REF": "refs/heads/main",
    "GITHUB_REPOSITORY": REPOSITORY,
    "GITHUB_REPOSITORY_ID": "1",
    "GITHUB_REPOSITORY_OWNER_ID": "1",
    "GITHUB_RUN_ATTEMPT": "1",
    "GITHUB_RUN_ID": "1",
    "GITHUB_SERVER_URL": "https://github.com",
    "GITHUB_SHA": "0" * 40,
    "GITHUB_WORKFLOW": "Publish (npm, OIDC)",
    "GITHUB_WORKFLOW_REF": f"{REPOSITORY}/.github/workflows/publish.yml@refs/heads/main",
    "RUNNER_ENVIRONMENT": "github-hosted",
}


@object_type
class PrivacyCore:
    """Run the same typed Privacy Core release graph locally and on GitHub."""

    source: dagger.Directory = field()

    @classmethod
    def create(cls, workspace: dagger.Workspace) -> Self:
        """Construct the graph from an explicit typed workspace snapshot."""
        instance = cls.__new__(cls)
        instance.source = workspace.directory("/", exclude=SOURCE_EXCLUDES)
        return instance

    @function
    def quality(self) -> dagger.Container:
        """Run lint, strict typing, coverage, browser proof, and build."""
        return self._quality(self.source)

    def _quality(self, source: dagger.Directory) -> dagger.Container:
        return self._playwright(source).with_exec(["pnpm", "gate"])

    @function
    def offline(self) -> dagger.Container:
        """Run the real Chromium offline and egress-boundary proof."""
        return self._playwright(self.source).with_exec(["pnpm", "test:e2e"])

    @function
    def dependency_audit(self) -> dagger.Container:
        """Audit the exact frozen pnpm graph without suppressions."""
        return self._dependency_audit(self.source)

    def _dependency_audit(self, source: dagger.Directory) -> dagger.Container:
        command = ["pnpm", "audit", "--audit-level", "moderate"]
        return self._dependencies(source).with_exec(command)

    @function
    def secret_scan(self, commit_sha: str = "") -> dagger.Container:
        """Scan the typed snapshot and complete canonical history."""
        return self._secret_scan(self.source, commit_sha)

    def _secret_scan(self, source: dagger.Directory, commit_sha: str = "") -> dagger.Container:
        history = self._history(commit_sha)
        scan = self._gitleaks().with_directory("/snapshot", source)
        scan = scan.with_exec(["sh", "-ceu", self._nonempty_snapshot()])
        scan = scan.with_exec(GITLEAKS_SNAPSHOT).with_directory("/repo", history)
        return scan.with_exec(GITLEAKS_HISTORY)

    @function
    def workflow_security(self) -> dagger.Container:
        """Validate every GitHub ingress workflow with pinned actionlint."""
        return self._workflow_security(self.source)

    def _workflow_security(self, source: dagger.Directory) -> dagger.Container:
        workflows = source.directory(".github/workflows")
        command = (
            "find .github/workflows -type f "
            "\\( -name '*.yml' -o -name '*.yaml' \\) -exec actionlint {} +"
        )
        return (
            self._actionlint()
            .with_directory("/repo/.github/workflows", workflows)
            .with_exec(["sh", "-ceu", command])
        )

    @function
    @check
    async def ci(self, commit_sha: str, repository: str = REPOSITORY) -> str:
        """Guard the exact caller source before the canonical product gate."""
        self._require_repository(repository)
        source = await self._verified_source(self.source, commit_sha, repository)
        await self._run_ci(source, commit_sha)
        return "Privacy Core canonical Dagger gate passed"

    async def _verified_source(
        self, source: dagger.Directory, commit_sha: str, repository: str
    ) -> dagger.Directory:
        """Bind and guard one exact caller snapshot before product evaluation."""
        self._require_sha(commit_sha)
        foundation = dag.foundation()
        bound = foundation.source(source, repository, commit_sha)
        await foundation.guard(bound, repository, commit_sha).sync()
        return bound

    @function
    def provenance_probe(self) -> dagger.Container:
        """Prove the publisher container's npm detects GitHub Actions and starts provenance."""
        return self._provenance_probe(self.source)

    def _provenance_probe(self, source: dagger.Directory) -> dagger.Container:
        """Run scripts/provenance-probe.mts in exactly the container `publish` builds."""
        environment = self._provenance_environment(json.dumps(PROBE_CONTEXT))
        url = dag.set_secret(
            "provenance-probe-oidc-url", f"http://127.0.0.1:{PROBE_PORT}/token?probe=1"
        )
        token = dag.set_secret("provenance-probe-oidc-token", "probe-not-a-token")
        probe = self._publisher(dag.directory(), url, token, environment)
        probe = probe.with_file("/probe/provenance-probe.mts", source.file(PROBE_SCRIPT))
        return probe.with_exec(["node", "/probe/provenance-probe.mts"])

    async def _run_ci(self, source: dagger.Directory, commit_sha: str = "") -> None:
        await self._quality(source).sync()
        await self._provenance_probe(source).sync()
        await self._dependency_audit(source).sync()
        await self._secret_scan(source, commit_sha).sync()
        await self._workflow_security(source).sync()

    @function
    async def release_candidate(
        self,
        tag: str,
        commit_sha: str,
        github_token: dagger.Secret,
        repository: str = REPOSITORY,
    ) -> dagger.Directory:
        """Build one exact Dagger-proven npm candidate without publishing."""
        self._require_tag(tag)
        self._require_sha(commit_sha)
        self._require_repository(repository)
        await self._hosted(commit_sha, tag, github_token, repository).sync()
        source = self._release_source(commit_sha)
        await self._identity(source, tag).sync()
        await self._run_ci(source, commit_sha)
        return self._candidate(source, tag).directory("/candidate")

    @function
    async def publish(
        self,
        candidate: dagger.Directory,
        expected_sha: str,
        oidc_url: dagger.Secret,
        oidc_token: dagger.Secret,
        github_context: dagger.File,
    ) -> str:
        """Publish one exact source-free candidate with npm OIDC provenance."""
        self._require_sha(expected_sha)
        environment = self._provenance_environment(await github_context.contents())
        archive = await self._candidate_archive(candidate)
        publish = self._publisher(candidate, oidc_url, oidc_token, environment)
        await publish.with_exec(["sha256sum", "--check", "SHA256SUMS"]).sync()
        # `./` makes the archive unconditionally a local path: npm reads an
        # `owner/repo`-shaped argument as a GitHub shorthand spec.
        command = ["npm", "publish", f"./{archive}", "--access", "public", "--provenance"]
        return await publish.with_exec(command).stdout()

    @staticmethod
    def _provenance_environment(context: str) -> dict[str, str]:
        """Validate the runner's GitHub Actions context into npm's environment."""
        parsed: object = json.loads(context)
        if not isinstance(parsed, dict) or set(parsed) != set(PROVENANCE_CONTEXT):
            raise ValueError("provenance context must carry exactly the npm provenance variables")
        values = {name: PrivacyCore._context_value(name, parsed[name]) for name in parsed}
        PrivacyCore._require_same_repository(values)
        return {"CI": "true", "GITHUB_ACTIONS": "true", **values}

    @staticmethod
    def _context_value(name: str, value: object) -> str:
        if not isinstance(value, str) or PROVENANCE_CONTEXT[name].fullmatch(value) is None:
            raise ValueError(f"provenance context {name} is not this repository's publisher")
        return value

    @staticmethod
    def _require_same_repository(values: dict[str, str]) -> None:
        workflow_repository = values["GITHUB_WORKFLOW_REF"].split("/.github/", 1)[0]
        if workflow_repository != values["GITHUB_REPOSITORY"]:
            raise ValueError("provenance context workflow ref is not this run's repository")

    @staticmethod
    async def _candidate_archive(candidate: dagger.Directory) -> str:
        entries = sorted(await candidate.entries())
        archives = [entry for entry in entries if ARCHIVE_NAME.fullmatch(entry)]
        archive = PrivacyCore._only_archive(entries, archives)
        checksum = await candidate.file("SHA256SUMS").contents()
        PrivacyCore._require_checksum(checksum, archive)
        return archive

    @staticmethod
    def _only_archive(entries: list[str], archives: list[str]) -> str:
        if len(archives) != 1:
            raise ValueError("candidate must contain one npm archive")
        if entries != ["SHA256SUMS", archives[0]]:
            raise ValueError("candidate must contain only the archive and SHA256SUMS")
        return archives[0]

    @staticmethod
    def _require_checksum(checksum: str, archive: str) -> None:
        match = CHECKSUM_LINE.fullmatch(checksum)
        if match is None or match.group("archive") != archive:
            raise ValueError("checksum identity does not match the npm archive")

    @staticmethod
    def _publisher(
        candidate: dagger.Directory,
        oidc_url: dagger.Secret,
        oidc_token: dagger.Secret,
        environment: dict[str, str],
    ) -> dagger.Container:
        base = dag.container().from_(NODE_IMAGE).with_directory("/release", candidate)
        for name, value in sorted(environment.items()):
            base = base.with_env_variable(name, value)
        base = base.with_workdir("/release").with_secret_variable(
            "ACTIONS_ID_TOKEN_REQUEST_URL", oidc_url
        )
        return base.with_secret_variable("ACTIONS_ID_TOKEN_REQUEST_TOKEN", oidc_token)

    def _hosted(
        self, commit_sha: str, tag: str, token: dagger.Secret, repository: str
    ) -> dagger.Container:
        command = self._contract_command("github", tag, commit_sha, repository)
        return (
            self._node(self.source).with_secret_variable("GITHUB_TOKEN", token).with_exec(command)
        )

    def _identity(self, source: dagger.Directory, tag: str) -> dagger.Container:
        command = [
            "node",
            "scripts/release-contract.ts",
            "identity",
            "--root",
            ".",
            "--tag",
            tag,
        ]
        return self._node(source).with_exec(command)

    def _candidate(self, source: dagger.Directory, tag: str) -> dagger.Container:
        version = tag.removeprefix("v")
        archive = f"/candidate/gainratio-privacy-core-{version}.tgz"
        built = self._dependencies(source).with_exec(["pnpm", "build"])
        built = self._candidate_root(built).with_exec(
            ["npm", "pack", "--ignore-scripts", "--pack-destination", "/candidate"]
        )
        built = built.with_exec(self._artifact_command(archive, tag))
        return built.with_exec(self._checksum_command(archive))

    @staticmethod
    def _candidate_root(built: dagger.Container) -> dagger.Container:
        """Create `/candidate` as root, then hand it to the runtime user.

        `_node` drops to 65532, which cannot create a directory directly under
        `/`. Same root-then-drop shape the Playwright cache already uses.
        """
        return (
            built.with_user("0:0")
            .with_exec(["mkdir", "-p", "/candidate"])
            .with_exec(["chown", "65532:65532", "/candidate"])
            .with_user("65532:65532")
        )

    @staticmethod
    def _artifact_command(archive: str, tag: str) -> list[str]:
        return [
            "node",
            "scripts/release-contract.ts",
            "artifact",
            "--root",
            ".",
            "--archive",
            archive,
            "--tag",
            tag,
        ]

    @staticmethod
    def _checksum_command(archive: str) -> list[str]:
        return [
            "node",
            "scripts/release-contract.ts",
            "checksum",
            "--archive",
            archive,
            "--output",
            "/candidate/SHA256SUMS",
        ]

    @staticmethod
    def _contract_command(command: str, tag: str, commit_sha: str, repository: str) -> list[str]:
        return [
            "node",
            "scripts/release-contract.ts",
            command,
            "--repository",
            repository,
            "--sha",
            commit_sha,
            "--tag",
            tag,
        ]

    def _playwright(self, source: dagger.Directory) -> dagger.Container:
        installed = self._dependencies(source).with_user("0:0")
        installed = installed.with_exec(PLAYWRIGHT_INSTALL)
        return installed.with_exec(["chown", "-R", "65532:65532", "/opt/playwright"]).with_user(
            "65532:65532"
        )

    def _dependencies(self, source: dagger.Directory) -> dagger.Container:
        return (
            self._node(source)
            .with_exec(["pnpm", "config", "set", "store-dir", "/opt/pnpm-store"])
            .with_exec(INSTALL_COMMAND)
        )

    def _node(self, source: dagger.Directory) -> dagger.Container:
        base = (
            self._node_toolchain()
            .with_directory("/src", source, owner="65532:65532")
            .with_workdir("/src")
        )
        base = base.with_env_variable("HOME", "/opt/home")
        base = base.with_env_variable("PLAYWRIGHT_BROWSERS_PATH", "/opt/playwright")
        base = base.with_mounted_cache(
            "/opt/pnpm-store", dag.cache_volume("privacy-core-pnpm"), owner="65532:65532"
        )
        base = base.with_exec(["mkdir", "-p", "/opt/home", "/opt/playwright"])
        base = base.with_exec(["chown", "-R", "65532:65532", "/opt/home", "/opt/playwright"])
        return base.with_user("65532:65532")

    @staticmethod
    def _node_toolchain() -> dagger.Container:
        base = dag.container().from_(NODE_IMAGE).with_exec(["corepack", "enable", "pnpm"])
        return base.with_exec(["corepack", "install", "--global", f"pnpm@{PNPM_VERSION}"])

    @staticmethod
    def _history(commit_sha: str) -> dagger.Directory:
        if commit_sha:
            PrivacyCore._require_sha(commit_sha)
            return PrivacyCore._release_source(commit_sha)
        return dag.git(REPOSITORY_URL).branch("main").tree(depth=0, include_tags=True)

    @staticmethod
    def _release_source(commit_sha: str) -> dagger.Directory:
        return dag.git(REPOSITORY_URL).commit(commit_sha).tree(depth=0, include_tags=True)

    @staticmethod
    def _actionlint() -> dagger.Container:
        return dag.container().from_(ACTIONLINT_IMAGE).with_entrypoint([]).with_workdir("/repo")

    @staticmethod
    def _gitleaks() -> dagger.Container:
        return dag.container().from_(GITLEAKS_IMAGE).with_entrypoint([])

    @staticmethod
    def _nonempty_snapshot() -> str:
        return 'test -n "$(find /snapshot -type f -print -quit)"'

    @staticmethod
    def _require_tag(tag: str) -> None:
        if RELEASE_TAG.fullmatch(tag) is None:
            raise ValueError("tag must be a plain vX.Y.Z release tag")

    @staticmethod
    def _require_repository(repository: str) -> None:
        if repository not in ALLOWED_REPOSITORIES:
            raise ValueError(f"repository must be one of {', '.join(ALLOWED_REPOSITORIES)}")

    @staticmethod
    def _require_sha(commit_sha: str) -> None:
        valid_length = len(commit_sha) == SHA_LENGTH
        valid = valid_length and all(char in "0123456789abcdef" for char in commit_sha)
        if not valid:
            raise ValueError("commit_sha must be a lowercase 40-character Git SHA")
