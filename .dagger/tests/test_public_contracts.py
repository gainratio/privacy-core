"""Behavioral contracts for Privacy Core's typed Dagger release graph."""

from __future__ import annotations

import asyncio
import inspect
import json
from pathlib import Path
from typing import cast

import dagger
import pytest

import privacy_core.main as main_module
from privacy_core.main import PrivacyCore

CENTRAL_SHA = "a895f726e9786bcfd2bdf68f87d3d5c4b411f702"
REPOSITORY = "hseshadr/privacy-core"
ORG_REPOSITORY = "gainratio/privacy-core"
PUBLISH_WORKFLOW_REF = "/.github/workflows/publish.yml@refs/heads/main"
ALLOWED = (REPOSITORY, ORG_REPOSITORY)
FOREIGN_REPOSITORIES = (
    "attacker/privacy-core",
    "gainratio/other-repo",
    "hseshadr/privacy-core-evil",
    "gainratio-evil/privacy-core",
    "",
)
VALID_SHA = "a" * 40


class RecordingWorkspace:
    """Record the explicit source root selected by the constructor."""

    def __init__(self) -> None:
        self.path = ""
        self.excludes: list[str] = []

    def directory(self, path: str, *, exclude: list[str]) -> dagger.Directory:
        self.path = path
        self.excludes = exclude
        return cast(dagger.Directory, object())


class CandidateFile:
    def __init__(self, contents: str) -> None:
        self._contents = contents

    async def contents(self) -> str:
        return self._contents


class RecordingCandidate:
    def __init__(self, entries: list[str], checksum: str) -> None:
        self._entries = entries
        self._checksum = checksum

    async def entries(self) -> list[str]:
        return self._entries

    def file(self, _path: str) -> dagger.File:
        return cast(dagger.File, CandidateFile(self._checksum))


class RecordingSync:
    """Record one forced Dagger boundary and optionally reject it."""

    def __init__(self, name: str, events: list[str], error: ValueError | None = None) -> None:
        self.name = name
        self.events = events
        self.error = error

    async def sync(self) -> None:
        if self.error is not None:
            raise self.error
        self.events.append(self.name)


class RecordingFoundation:
    """Model the exact source-binding and guard boundary."""

    def __init__(
        self, events: list[str], error: ValueError | None = None, repository: str = REPOSITORY
    ) -> None:
        self.events = events
        self.error = error
        self.repository = repository
        self.bound = cast(dagger.Directory, "bound-source")

    def source(
        self, source: dagger.Directory, repository: str, commit_sha: str
    ) -> dagger.Directory:
        assert (source, repository, commit_sha) == ("caller-source", self.repository, VALID_SHA)
        self.events.append("source")
        return self.bound

    def guard(self, source: dagger.Directory, repository: str, commit_sha: str) -> dagger.Container:
        assert (source, repository, commit_sha) == (self.bound, self.repository, VALID_SHA)
        return cast(dagger.Container, RecordingSync("guard", self.events, self.error))


class RecordingDag:
    """Expose only the Foundation client used by the canonical check."""

    def __init__(self, foundation: RecordingFoundation) -> None:
        self.foundation_client = foundation

    def foundation(self) -> RecordingFoundation:
        return self.foundation_client


def test_should_select_an_explicit_typed_workspace_root() -> None:
    workspace = RecordingWorkspace()

    PrivacyCore.create(cast(dagger.Workspace, workspace))

    assert workspace.path == "/"
    assert ".git" in workspace.excludes
    assert "node_modules" in workspace.excludes


def test_should_exclude_generated_python_gate_state_from_source_binding() -> None:
    # Given
    workspace = RecordingWorkspace()

    # When
    PrivacyCore.create(cast(dagger.Workspace, workspace))

    # Then
    assert {
        ".dagger/.mypy_cache",
        ".dagger/.pytest_cache",
        ".dagger/.ruff_cache",
    } <= set(workspace.excludes)


def test_should_require_typed_workspace_when_constructing_graph() -> None:
    signature = inspect.signature(PrivacyCore.create, eval_str=True)

    workspace = signature.parameters.get("workspace")

    assert workspace is not None
    assert workspace.annotation is dagger.Workspace


def test_should_expose_canonical_gate_and_release_boundaries() -> None:
    expected = {
        "ci",
        "quality",
        "dependency_audit",
        "offline",
        "publish",
        "secret_scan",
        "workflow_security",
        "release_candidate",
        "provenance_probe",
    }

    available = {name for name in expected if hasattr(PrivacyCore, name)}

    assert available == expected


def test_should_require_a_typed_secret_for_hosted_eligibility() -> None:
    signature = inspect.signature(PrivacyCore.release_candidate, eval_str=True)

    token = signature.parameters.get("github_token")

    assert token is not None
    assert token.annotation is dagger.Secret
    assert signature.return_annotation is dagger.Directory


def test_should_keep_the_source_free_publisher_typed_and_provenanced() -> None:
    signature = inspect.signature(PrivacyCore.publish, eval_str=True)
    implementation = inspect.getsource(PrivacyCore.publish)

    assert signature.parameters["candidate"].annotation is dagger.Directory
    assert signature.parameters["oidc_url"].annotation is dagger.Secret
    assert signature.parameters["oidc_token"].annotation is dagger.Secret
    assert "--provenance" in implementation
    assert "npm" in implementation


def test_should_accept_only_one_checksumming_npm_candidate() -> None:
    archive = "gainratio-privacy-core-1.2.3.tgz"
    candidate = RecordingCandidate([archive, "SHA256SUMS"], f"{'a' * 64}  {archive}\n")

    result = asyncio.run(PrivacyCore._candidate_archive(cast(dagger.Directory, candidate)))

    assert result == archive


def test_should_reject_extra_or_misidentified_candidate_material() -> None:
    archive = "gainratio-privacy-core-1.2.3.tgz"
    candidate = RecordingCandidate([archive, "SHA256SUMS", "source.ts"], f"{'a' * 64}  other.tgz\n")

    with pytest.raises(ValueError, match="candidate must contain only"):
        asyncio.run(PrivacyCore._candidate_archive(cast(dagger.Directory, candidate)))


def test_should_pin_node_and_the_repository_package_manager() -> None:
    module = inspect.getmodule(PrivacyCore)

    assert module is not None
    assert "node:24.16.0-bookworm-slim@sha256:" in module.NODE_IMAGE
    assert module.PNPM_VERSION == "11.5.0"


def test_should_scan_snapshot_history_and_both_workflow_extensions() -> None:
    secret_scan = inspect.getsource(PrivacyCore._secret_scan)
    workflow_security = inspect.getsource(PrivacyCore._workflow_security)

    assert "GITLEAKS_SNAPSHOT" in secret_scan
    assert "GITLEAKS_HISTORY" in secret_scan
    assert "*.yml" in workflow_security
    assert "*.yaml" in workflow_security


def test_should_install_frozen_dependencies_without_the_global_escape_hatch() -> None:
    implementation = inspect.getsource(PrivacyCore)
    module = inspect.getmodule(PrivacyCore)

    assert module is not None
    assert module.INSTALL_COMMAND == ["pnpm", "install", "--frozen-lockfile"]
    assert "dangerously-allow-all-builds" not in implementation
    assert '["pnpm", "gate"]' in implementation


def test_should_pin_foundation_to_the_exact_central_commit() -> None:
    # Given
    config = json.loads((Path(__file__).parents[2] / "dagger.json").read_text())

    # When
    dependencies = config.get("dependencies", [])

    # Then
    assert dependencies == [
        {
            "name": "foundation",
            "source": f"github.com/hseshadr/ci/modules/portfolio-foundation@{CENTRAL_SHA}",
            "pin": CENTRAL_SHA,
        }
    ]


def test_should_require_an_explicit_commit_for_the_canonical_check() -> None:
    # Given / When
    signature = inspect.signature(PrivacyCore.ci)

    # Then
    assert signature.parameters["commit_sha"].default is inspect.Signature.empty


def test_should_bind_guard_then_run_products_on_the_bound_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    events: list[str] = []
    foundation = RecordingFoundation(events)
    core = PrivacyCore.__new__(PrivacyCore)
    core.source = cast(dagger.Directory, "caller-source")

    async def run_products(source: dagger.Directory, *_identity: object) -> None:
        assert source == foundation.bound
        events.append("product")

    monkeypatch.setattr(main_module, "dag", RecordingDag(foundation))
    monkeypatch.setattr(core, "_run_ci", run_products)

    # When
    result = asyncio.run(core.ci(VALID_SHA))

    # Then
    assert result == "Privacy Core canonical Dagger gate passed"
    assert events == ["source", "guard", "product"]


def test_should_stop_before_products_when_foundation_rejects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    events: list[str] = []
    foundation = RecordingFoundation(events, ValueError("guard rejected"))
    core = PrivacyCore.__new__(PrivacyCore)
    core.source = cast(dagger.Directory, "caller-source")

    async def run_products(*_arguments: object) -> None:
        events.append("product")

    monkeypatch.setattr(main_module, "dag", RecordingDag(foundation))
    monkeypatch.setattr(core, "_run_ci", run_products)

    # When / Then
    with pytest.raises(ValueError, match="guard rejected"):
        asyncio.run(core.ci(VALID_SHA))
    assert events == ["source"]


# Repository identity: the run's own `github.repository`, checked by exact
# membership in a two-item allow-list. The org move (hseshadr -> gainratio)
# changes the run's identity; no other owner and no other repo may pass.
def test_should_allow_exactly_the_user_and_org_repositories() -> None:
    assert main_module.ALLOWED_REPOSITORIES == (
        "hseshadr/privacy-core",
        "gainratio/privacy-core",
    )


def test_should_default_every_identity_argument_to_todays_repository() -> None:
    for function in (PrivacyCore.ci, PrivacyCore.release_candidate):
        parameter = inspect.signature(function).parameters["repository"]
        assert parameter.default == "hseshadr/privacy-core"


def recording_core(
    foundation: RecordingFoundation, events: list[str], monkeypatch: pytest.MonkeyPatch
) -> PrivacyCore:
    core = PrivacyCore.__new__(PrivacyCore)
    core.source = cast(dagger.Directory, "caller-source")

    async def run_products(*_arguments: object) -> None:
        events.append("product")

    monkeypatch.setattr(main_module, "dag", RecordingDag(foundation))
    monkeypatch.setattr(core, "_run_ci", run_products)
    return core


@pytest.mark.parametrize("repository", ALLOWED)
def test_should_bind_and_guard_the_runs_own_allowed_repository(
    repository: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given
    events: list[str] = []
    core = recording_core(RecordingFoundation(events, repository=repository), events, monkeypatch)

    # When
    asyncio.run(core.ci(VALID_SHA, repository))

    # Then
    assert events == ["source", "guard", "product"]


@pytest.mark.parametrize("repository", FOREIGN_REPOSITORIES)
def test_should_refuse_a_foreign_repository_before_foundation_runs(
    repository: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given
    events: list[str] = []
    core = recording_core(RecordingFoundation(events), events, monkeypatch)

    # When / Then
    with pytest.raises(ValueError, match="repository"):
        asyncio.run(core.ci(VALID_SHA, repository))
    assert events == []


@pytest.mark.parametrize("repository", FOREIGN_REPOSITORIES)
def test_should_refuse_a_foreign_repository_before_hosted_release_lookup(
    repository: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given
    core = PrivacyCore.__new__(PrivacyCore)

    def hosted(*_arguments: object) -> None:
        raise AssertionError("hosted lookup must not run for a foreign repository")

    monkeypatch.setattr(core, "_hosted", hosted)

    # When / Then
    with pytest.raises(ValueError, match="repository"):
        asyncio.run(
            core.release_candidate("v1.2.3", VALID_SHA, cast(dagger.Secret, object()), repository)
        )


@pytest.mark.parametrize("repository", ALLOWED)
def test_should_look_up_hosted_release_state_for_the_runs_repository(
    repository: str,
) -> None:
    command = PrivacyCore._contract_command("github", "v1.2.3", VALID_SHA, repository)

    assert command[command.index("--repository") + 1] == repository


# The GitHub Actions variables npm 11.13.0 (bundled with the pinned node:24.16.0
# image) reads to detect GitHub Actions (ci-info: GITHUB_ACTIONS) and to write
# the SLSA provenance statement (libnpmpublish/lib/provenance.js). Without them
# `npm publish --provenance` fails with
# `EUSAGE: Automatic provenance generation not supported for provider: null`,
# and the npm OIDC trusted-publishing exchange (lib/utils/oidc.js) is skipped.
NPM_PROVENANCE_READS = {
    "GITHUB_EVENT_NAME",
    "GITHUB_REF",
    "GITHUB_REPOSITORY",
    "GITHUB_REPOSITORY_ID",
    "GITHUB_REPOSITORY_OWNER_ID",
    "GITHUB_RUN_ATTEMPT",
    "GITHUB_RUN_ID",
    "GITHUB_SERVER_URL",
    "GITHUB_SHA",
    "GITHUB_WORKFLOW_REF",
    "RUNNER_ENVIRONMENT",
}

VALID_CONTEXT = {
    "GITHUB_EVENT_NAME": "workflow_run",
    "GITHUB_REF": "refs/heads/main",
    "GITHUB_REPOSITORY": REPOSITORY,
    "GITHUB_REPOSITORY_ID": "1012345678",
    "GITHUB_REPOSITORY_OWNER_ID": "4185618",
    "GITHUB_RUN_ATTEMPT": "1",
    "GITHUB_RUN_ID": "17123456789",
    "GITHUB_SERVER_URL": "https://github.com",
    "GITHUB_SHA": VALID_SHA,
    "GITHUB_WORKFLOW": "Publish (npm, OIDC)",
    "GITHUB_WORKFLOW_REF": f"{REPOSITORY}/.github/workflows/publish.yml@refs/heads/main",
    "RUNNER_ENVIRONMENT": "github-hosted",
}


class RecordingContainer:
    """Record every environment, secret, and exec call on one container chain."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []

    def from_(self, image: str) -> RecordingContainer:
        self.calls.append(("from", image))
        return self

    def with_directory(self, path: str, _directory: object) -> RecordingContainer:
        self.calls.append(("directory", path))
        return self

    def with_workdir(self, path: str) -> RecordingContainer:
        self.calls.append(("workdir", path))
        return self

    def with_secret_variable(self, name: str, _secret: object) -> RecordingContainer:
        self.calls.append(("secret", name))
        return self

    def with_env_variable(self, name: str, value: str) -> RecordingContainer:
        self.calls.append(("env", (name, value)))
        return self

    def with_file(self, path: str, _file: object) -> RecordingContainer:
        self.calls.append(("file", path))
        return self

    def with_exec(self, command: list[str]) -> RecordingContainer:
        self.calls.append(("exec", command))
        return self

    async def sync(self) -> RecordingContainer:
        return self

    async def stdout(self) -> str:
        return "published"


class ContainerDag:
    def __init__(self, container: RecordingContainer) -> None:
        self.recording = container
        self.secrets: dict[str, str] = {}

    def container(self) -> RecordingContainer:
        return self.recording

    def directory(self) -> object:
        return object()

    def set_secret(self, name: str, value: str) -> str:
        self.secrets[name] = value
        return name


class ProbeSource:
    def __init__(self) -> None:
        self.files: list[str] = []

    def file(self, path: str) -> object:
        self.files.append(path)
        return object()


def publish_with(context: str, monkeypatch: pytest.MonkeyPatch) -> RecordingContainer:
    archive = "gainratio-privacy-core-1.2.3.tgz"
    candidate = RecordingCandidate([archive, "SHA256SUMS"], f"{'a' * 64}  {archive}\n")
    container = RecordingContainer()
    monkeypatch.setattr(main_module, "dag", ContainerDag(container))
    core = PrivacyCore.__new__(PrivacyCore)
    result = asyncio.run(
        core.publish(
            cast(dagger.Directory, candidate),
            VALID_SHA,
            cast(dagger.Secret, object()),
            cast(dagger.Secret, object()),
            cast(dagger.File, CandidateFile(context)),
        )
    )
    assert result == "published"
    return container


def test_should_hand_npm_every_github_actions_provenance_variable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given / When
    container = publish_with(json.dumps(VALID_CONTEXT), monkeypatch)

    # Then
    env = dict(cast(tuple[str, str], value) for kind, value in container.calls if kind == "env")
    assert env["GITHUB_ACTIONS"] == "true"
    assert env["CI"] == "true"
    assert set(env) >= NPM_PROVENANCE_READS
    assert {name: env[name] for name in VALID_CONTEXT} == VALID_CONTEXT
    secrets = {value for kind, value in container.calls if kind == "secret"}
    assert secrets == {"ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"}


def test_should_set_the_provenance_context_before_npm_publish_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given / When
    container = publish_with(json.dumps(VALID_CONTEXT), monkeypatch)

    # Then
    execs = [index for index, (kind, _) in enumerate(container.calls) if kind == "exec"]
    last_env = max(index for index, (kind, _) in enumerate(container.calls) if kind == "env")
    publish = container.calls[execs[-1]][1]
    assert last_env < execs[0]
    assert publish == [
        "npm",
        "publish",
        "./gainratio-privacy-core-1.2.3.tgz",
        "--access",
        "public",
        "--provenance",
    ]


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"GITHUB_REPOSITORY": "attacker/privacy-core"}, "foreign repository"),
        ({"GITHUB_REPOSITORY": "gainratio/other-repo"}, "other org repository"),
        ({"GITHUB_REPOSITORY": "hseshadr/privacy-core-evil"}, "suffixed repository"),
        ({"GITHUB_REPOSITORY": "gainratio-evil/privacy-core"}, "lookalike owner"),
        ({"GITHUB_REPOSITORY": ""}, "empty repository"),
        (
            {"GITHUB_WORKFLOW_REF": f"{ORG_REPOSITORY}{PUBLISH_WORKFLOW_REF}"},
            "workflow ref from a different repository than the run",
        ),
        (
            {
                "GITHUB_REPOSITORY": "attacker/privacy-core",
                "GITHUB_WORKFLOW_REF": f"attacker/privacy-core{PUBLISH_WORKFLOW_REF}",
            },
            "foreign repository with a matching workflow ref",
        ),
        (
            {"GITHUB_WORKFLOW_REF": f"{REPOSITORY}/.github/workflows/other.yml@refs/heads/main"},
            "workflow other than the trusted publisher",
        ),
        ({"RUNNER_ENVIRONMENT": "self-hosted"}, "self-hosted runner"),
        ({"GITHUB_SERVER_URL": "https://evil.example"}, "foreign server"),
        ({"GITHUB_SHA": "not-a-sha"}, "malformed sha"),
        ({"GITHUB_RUN_ID": "1\nNPM_TOKEN=x"}, "newline injection"),
        ({"GITHUB_WORKFLOW": "Publish\n"}, "control character"),
        ({"GITHUB_RUN_ATTEMPT": 1}, "non-string value"),
        ({"NPM_TOKEN": "smuggled"}, "unexpected variable"),
    ],
)
def test_should_refuse_a_provenance_context_that_is_not_this_publisher(
    change: dict[str, object], reason: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given
    context = {**VALID_CONTEXT, **change}

    # When / Then
    with pytest.raises(ValueError, match="provenance context"):
        publish_with(json.dumps(context), monkeypatch)
    assert reason


@pytest.mark.parametrize("repository", ALLOWED)
def test_should_publish_from_the_user_or_org_repository(
    repository: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given
    workflow_ref = f"{repository}/.github/workflows/publish.yml@refs/heads/main"
    context = {
        **VALID_CONTEXT,
        "GITHUB_REPOSITORY": repository,
        "GITHUB_WORKFLOW_REF": workflow_ref,
    }

    # When
    container = publish_with(json.dumps(context), monkeypatch)

    # Then
    env = dict(cast(tuple[str, str], value) for kind, value in container.calls if kind == "env")
    assert (env["GITHUB_REPOSITORY"], env["GITHUB_WORKFLOW_REF"]) == (repository, workflow_ref)


@pytest.mark.parametrize("repository", FOREIGN_REPOSITORIES)
@pytest.mark.parametrize(
    ("name", "suffix"), [("GITHUB_REPOSITORY", ""), ("GITHUB_WORKFLOW_REF", PUBLISH_WORKFLOW_REF)]
)
def test_should_refuse_a_foreign_repository_in_each_identity_variable(
    repository: str, name: str, suffix: str
) -> None:
    # Given: each identity variable is checked on its own, not only via the other
    value = f"{repository}{suffix}"

    # When / Then
    with pytest.raises(ValueError, match="provenance context"):
        PrivacyCore._context_value(name, value)


@pytest.mark.parametrize("repository", ALLOWED)
@pytest.mark.parametrize(
    ("name", "suffix"), [("GITHUB_REPOSITORY", ""), ("GITHUB_WORKFLOW_REF", PUBLISH_WORKFLOW_REF)]
)
def test_should_accept_an_allowed_repository_in_each_identity_variable(
    repository: str, name: str, suffix: str
) -> None:
    value = f"{repository}{suffix}"

    assert PrivacyCore._context_value(name, value) == value


@pytest.mark.parametrize("payload", ["[]", "null", "{}", json.dumps({"GITHUB_SHA": VALID_SHA})])
def test_should_refuse_a_provenance_context_missing_variables(
    payload: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(ValueError, match="provenance context"):
        publish_with(payload, monkeypatch)


@pytest.mark.parametrize("tag", ["v1.2.3'", "v1.2", "1.2.3", "v01.2.3", "v1.2.3-rc.1", "v1.2.3\n"])
def test_should_refuse_a_release_tag_that_is_not_plain_semver(tag: str) -> None:
    core = PrivacyCore.__new__(PrivacyCore)

    with pytest.raises(ValueError, match="tag"):
        asyncio.run(core.release_candidate(tag, VALID_SHA, cast(dagger.Secret, object())))


def test_should_probe_npm_provenance_in_exactly_the_publisher_container(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    container = RecordingContainer()
    fake = ContainerDag(container)
    monkeypatch.setattr(main_module, "dag", fake)
    source = ProbeSource()
    core = PrivacyCore.__new__(PrivacyCore)

    # When
    core._provenance_probe(cast(dagger.Directory, source))

    # Then: the same image, the same validated provenance env, the same OIDC
    # variable names — pointed at the probe's loopback stub — then the probe.
    env = dict(cast(tuple[str, str], value) for kind, value in container.calls if kind == "env")
    assert ("from", main_module.NODE_IMAGE) in container.calls
    assert env["GITHUB_ACTIONS"] == "true"
    assert set(env) >= NPM_PROVENANCE_READS
    secrets = {value for kind, value in container.calls if kind == "secret"}
    assert secrets == {"ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"}
    assert fake.secrets["provenance-probe-oidc-url"].startswith("http://127.0.0.1:")
    assert source.files == ["scripts/provenance-probe.mts"]
    assert container.calls[-1] == ("exec", ["node", "/probe/provenance-probe.mts"])


def test_should_run_the_provenance_probe_in_the_canonical_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    events: list[str] = []
    core = PrivacyCore.__new__(PrivacyCore)
    for name in ("_quality", "_provenance_probe", "_dependency_audit", "_workflow_security"):
        monkeypatch.setattr(
            core,
            name,
            lambda *_args, label=name: RecordingSync(label, events),
        )
    monkeypatch.setattr(core, "_secret_scan", lambda *_args: RecordingSync("_secret_scan", events))

    # When
    asyncio.run(core._run_ci(cast(dagger.Directory, "source"), VALID_SHA))

    # Then
    assert events == [
        "_quality",
        "_provenance_probe",
        "_dependency_audit",
        "_secret_scan",
        "_workflow_security",
    ]


def test_should_hand_npm_publish_a_path_it_can_never_read_as_a_spec(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: npm reads `owner/repo`-shaped arguments as GitHub shorthand (the
    # failure @edgeproc/errors hit with `release/x.tgz`); only an explicit
    # `./` or `/` prefix is unconditionally a local path.
    container = publish_with(json.dumps(VALID_CONTEXT), monkeypatch)

    # When
    execs = [value for kind, value in container.calls if kind == "exec"]
    publish = cast(list[str], execs[-1])

    # Then
    assert publish[:2] == ["npm", "publish"]
    assert publish[2].startswith(("./", "/"))


class PrivilegeAwareContainer(RecordingContainer):
    """`RecordingContainer` plus the one runtime rule the release graph broke:
    only root may create a directory directly beneath `/`."""

    def __init__(self) -> None:
        super().__init__()
        self.user = "0:0"

    def with_user(self, user: str) -> PrivilegeAwareContainer:
        self.user = user
        self.calls.append(("user", user))
        return self

    def with_directory(
        self, path: str, _directory: object, *, owner: str = ""
    ) -> PrivilegeAwareContainer:
        self.calls.append(("directory", path))
        return self

    def with_mounted_cache(
        self, path: str, _cache: object, *, owner: str = ""
    ) -> PrivilegeAwareContainer:
        self.calls.append(("cache", path))
        return self

    def with_exec(self, command: list[str]) -> PrivilegeAwareContainer:
        if command and command[0] == "mkdir":
            self._refuse_unprivileged_root_write(command[1:])
        self.calls.append(("exec", command))
        return self

    def _refuse_unprivileged_root_write(self, targets: list[str]) -> None:
        if self.user == "0:0":
            return
        for target in targets:
            if target.startswith("/") and target.count("/") == 1:
                raise PermissionError(
                    f"mkdir: cannot create directory '{target}': Permission denied"
                )


class PrivilegeDag(ContainerDag):
    """`ContainerDag` that also serves the pnpm cache volume the node base mounts."""

    def cache_volume(self, _name: str) -> object:
        return object()


def test_should_build_the_candidate_without_an_unprivileged_root_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    container = PrivilegeAwareContainer()
    monkeypatch.setattr(main_module, "dag", PrivilegeDag(container))
    core = PrivacyCore.__new__(PrivacyCore)

    # When
    core._candidate(cast(dagger.Directory, "caller-source"), "v0.3.0")

    # Then
    execs = [cast(list[str], command) for kind, command in container.calls if kind == "exec"]
    assert ["mkdir", "-p", "/candidate"] in execs
    assert any(command[:2] == ["npm", "pack"] for command in execs)


def test_should_model_the_root_directory_permission_rule() -> None:
    # Given / When / Then — root may create a directory directly under `/`.
    PrivilegeAwareContainer().with_exec(["mkdir", "-p", "/candidate"])

    # The runtime user may not, which is exactly how the v0.3.0 release died.
    dropped = PrivilegeAwareContainer().with_user("65532:65532")
    with pytest.raises(PermissionError, match="/candidate"):
        dropped.with_exec(["mkdir", "-p", "/candidate"])

    # Nested paths under an existing writable tree stay allowed for any user.
    dropped.with_exec(["mkdir", "-p", "/opt/home", "/opt/playwright"])
