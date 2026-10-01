import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";

const PACKAGE = "@gainratio/privacy-core";
const SHA = /^[0-9a-f]{40}$/;
const VERSION = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/;
type Json = Readonly<Record<string, unknown>>;
type Options = Readonly<Record<string, string>>;

function fail(message: string): never {
  throw new Error(message);
}

function asJson(value: unknown, label: string): Json {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
  return value as Json;
}

function readJson(path: string): Json {
  return asJson(JSON.parse(readFileSync(path, "utf8")) as unknown, path);
}

function options(args: readonly string[]): Options {
  if (args.length % 2 !== 0) fail("options require --name value pairs");
  const parsed: Record<string, string> = {};
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index];
    const value = args[index + 1];
    if (!key?.startsWith("--") || value === undefined) fail("invalid option");
    parsed[key.slice(2)] = value;
  }
  return parsed;
}

function required(values: Options, key: string): string {
  const value = values[key];
  if (value === undefined || value === "") fail(`missing --${key}`);
  return value;
}

function packageIdentity(root: string): Readonly<{ version: string }> {
  const manifest = readJson(join(root, "package.json"));
  if (manifest.name !== PACKAGE) fail(`package name must be ${PACKAGE}`);
  if (typeof manifest.version !== "string" || !VERSION.test(manifest.version)) {
    fail("package version must be stable semver");
  }
  return { version: manifest.version };
}

function latestStableVersion(root: string): string {
  const changelog = readFileSync(join(root, "CHANGELOG.md"), "utf8");
  const headings = [...changelog.matchAll(/^## \[([^\]]+)]/gm)];
  const stable = headings
    .map((match) => match[1])
    .find((value) => value !== "Unreleased");
  if (stable === undefined || !VERSION.test(stable)) {
    fail("missing stable changelog entry");
  }
  return stable;
}

function identity(values: Options): Readonly<{ version: string }> {
  const root = required(values, "root");
  const tag = required(values, "tag");
  const result = packageIdentity(root);
  if (tag !== `v${result.version}`) fail("tag does not match package version");
  if (latestStableVersion(root) !== result.version) {
    fail("changelog does not match package version");
  }
  return result;
}

function validateHosted(payload: Json, expected: string): void {
  if (!SHA.test(expected)) fail("expected SHA must be lowercase 40-hex");
  if (payload.mainSha !== expected || payload.tagSha !== expected) {
    fail("tag and main must equal expected SHA");
  }
  const checks = Array.isArray(payload.checks)
    ? payload.checks.map((item) => asJson(item, "check"))
    : fail("checks must be an array");
  const dagger = checks.filter((check) => check.name === "Dagger");
  const successful = dagger.filter(
    (check) => check.headSha === expected && check.conclusion === "success",
  );
  if (dagger.length !== 1 || successful.length !== 1) {
    fail("exactly one successful Dagger check is required");
  }
}

function hosted(values: Options): void {
  validateHosted(
    readJson(required(values, "payload")),
    required(values, "sha"),
  );
}

async function githubJson(url: string, token: string): Promise<Json> {
  const response = await fetch(url, {
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "X-GitHub-Api-Version": "2022-11-28",
    },
  });
  if (!response.ok) fail(`GitHub API returned ${response.status}`);
  return asJson((await response.json()) as unknown, url);
}

async function github(values: Options): Promise<void> {
  const repository = required(values, "repository");
  const expected = required(values, "sha");
  const tag = required(values, "tag");
  const token = process.env.GITHUB_TOKEN;
  if (token === undefined || token === "") fail("GITHUB_TOKEN is required");
  if (!/^[\w.-]+\/[\w.-]+$/.test(repository)) fail("invalid repository");
  const api = values.api ?? "https://api.github.com";
  const base = `${api}/repos/${repository}/commits`;
  const main = await githubJson(`${base}/main`, token);
  const tagged = await githubJson(`${base}/${encodeURIComponent(tag)}`, token);
  const checks = await githubJson(`${base}/${expected}/check-runs`, token);
  const runs = Array.isArray(checks.check_runs)
    ? checks.check_runs
    : fail("missing check runs");
  validateHosted(
    {
      mainSha: main.sha,
      tagSha: tagged.sha,
      checks: runs.map((run) => {
        const check = asJson(run, "check run");
        return {
          name: check.name,
          headSha: check.head_sha,
          conclusion: check.conclusion,
        };
      }),
    },
    expected,
  );
}

function archiveEntries(archive: string): readonly string[] {
  const listed = spawnSync("tar", ["-tzf", archive], { encoding: "utf8" });
  if (listed.status !== 0) fail(`cannot inspect archive: ${listed.stderr}`);
  const entries = listed.stdout.split("\n").filter(Boolean);
  if (entries.length === 0) fail("archive is empty");
  if (
    entries.some(
      (entry) => !entry.startsWith("package/") || entry.includes(".."),
    )
  ) {
    fail("unsafe archive path");
  }
  return entries;
}

function validatePackageEntries(entries: readonly string[]): void {
  const names = new Set(entries.map((entry) => entry.replace(/\/$/, "")));
  const requiredEntries = [
    "package/LICENSE",
    "package/README.md",
    "package/package.json",
    "package/dist/index.js",
    "package/dist/index.d.ts",
    "package/dist/testing.js",
    "package/dist/testing.d.ts",
  ];
  if (requiredEntries.some((entry) => !names.has(entry))) {
    fail("archive is missing a required public package file");
  }
  const allowedRoot = new Set([
    "package",
    "package/dist",
    ...requiredEntries.slice(0, 3),
  ]);
  if (
    [...names].some(
      (entry) => !allowedRoot.has(entry) && !entry.startsWith("package/dist/"),
    )
  ) {
    fail("archive contains non-public source or build material");
  }
}

function exportTargets(value: unknown): readonly string[] {
  if (typeof value === "string") return [value];
  if (typeof value !== "object" || value === null || Array.isArray(value))
    return [];
  return Object.values(value).flatMap(exportTargets);
}

function unpack(
  archive: string,
): Readonly<{ root: string; entries: readonly string[] }> {
  const root = mkdtempSync(join(tmpdir(), "privacy-core-artifact-"));
  const entries = archiveEntries(archive);
  const result = spawnSync("tar", ["-xzf", archive, "-C", root], {
    encoding: "utf8",
  });
  if (result.status !== 0) fail(`cannot extract archive: ${result.stderr}`);
  return { root, entries };
}

function validateExports(root: string, manifest: Json): void {
  const targets = exportTargets(manifest.exports);
  if (targets.length === 0) fail("package exports are required");
  for (const target of targets) {
    if (!target.startsWith("./") || !existsSync(resolve(root, target))) {
      fail(`missing package export: ${target}`);
    }
  }
}

function artifact(values: Options): void {
  const expected = identity(values);
  const archive = required(values, "archive");
  if (basename(archive) !== `gainratio-privacy-core-${expected.version}.tgz`) {
    fail("archive filename does not match package version");
  }
  const extracted = unpack(archive);
  try {
    validatePackageEntries(extracted.entries);
    const root = join(extracted.root, "package");
    const packed = packageIdentity(root);
    if (packed.version !== expected.version)
      fail("archive version does not match source");
    validateExports(root, readJson(join(root, "package.json")));
  } finally {
    rmSync(extracted.root, { recursive: true, force: true });
  }
}

function checksum(values: Options): void {
  const archive = required(values, "archive");
  const output = required(values, "output");
  const digest = createHash("sha256")
    .update(readFileSync(archive))
    .digest("hex");
  writeFileSync(output, `${digest}  ${basename(archive)}\n`);
}

async function validate(command: string, values: Options): Promise<void> {
  if (command === "identity") identity(values);
  else if (command === "hosted") hosted(values);
  else if (command === "github") await github(values);
  else if (command === "artifact") artifact(values);
  else if (command === "checksum") checksum(values);
  else fail(`unknown command: ${command}`);
}

async function main(args: readonly string[]): Promise<void> {
  const [command, ...rest] = args;
  if (command === undefined) fail("missing command");
  await validate(command, options(rest));
}

try {
  await main(process.argv.slice(2));
} catch (error: unknown) {
  process.stderr.write(
    `${error instanceof Error ? error.message : String(error)}\n`,
  );
  process.exitCode = 1;
}
