import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";

const SCRIPT = resolve(import.meta.dirname, "../scripts/release-contract.ts");
const SHA = "a".repeat(40);

function runContract(...args: readonly string[]) {
  // Hermetic: an ambient GITHUB_TOKEN/GH_TOKEN on a developer machine or agent
  // sandbox would otherwise send the "missing token" case to the live API.
  const { GITHUB_TOKEN: _token, GH_TOKEN: _gh, ...env } = process.env;
  return spawnSync(process.execPath, [SCRIPT, ...args], {
    encoding: "utf8",
    env,
  });
}

function expectRejected(...args: readonly string[]): void {
  const result = runContract(...args);
  expect(result.status).toBe(1);
  expect(result.stderr).not.toBe("");
}

function sourceFixture(): string {
  const root = mkdtempSync(join(tmpdir(), "privacy-core-source-"));
  writeFileSync(
    join(root, "package.json"),
    JSON.stringify({ name: "@gainratio/privacy-core", version: "1.2.3" }),
  );
  writeFileSync(
    join(root, "CHANGELOG.md"),
    "# Changelog\n\n## [Unreleased]\n\n## [1.2.3] — 2026-08-26\n",
  );
  return root;
}

function packageFixture(root: string): string {
  const packageRoot = join(root, "package");
  mkdirSync(join(packageRoot, "dist"), { recursive: true });
  writeFileSync(join(packageRoot, "LICENSE"), "MIT\n");
  writeFileSync(join(packageRoot, "README.md"), "# Privacy Core\n");
  writeFileSync(
    join(packageRoot, "package.json"),
    JSON.stringify({
      name: "@gainratio/privacy-core",
      version: "1.2.3",
      files: ["dist"],
      exports: { ".": "./dist/index.js", "./testing": "./dist/testing.js" },
    }),
  );
  writeFileSync(
    join(packageRoot, "dist/index.js"),
    "export const ready = true;\n",
  );
  writeFileSync(
    join(packageRoot, "dist/testing.js"),
    "export const fixture = true;\n",
  );
  writeFileSync(join(packageRoot, "dist/index.d.ts"), "export {};\n");
  writeFileSync(join(packageRoot, "dist/testing.d.ts"), "export {};\n");
  const archive = join(root, "gainratio-privacy-core-1.2.3.tgz");
  const packed = spawnSync("tar", ["-czf", archive, "package"], { cwd: root });
  expect(packed.status).toBe(0);
  return archive;
}

describe("release candidate contract", () => {
  it("accepts matching source, hosted, and package identities", () => {
    const root = sourceFixture();
    const archive = packageFixture(root);
    const payload = join(root, "hosted.json");
    const checksum = join(root, "SHA256SUMS");
    writeFileSync(
      payload,
      JSON.stringify({
        mainSha: SHA,
        tagSha: SHA,
        checks: [{ name: "Dagger", headSha: SHA, conclusion: "success" }],
      }),
    );

    expect(
      runContract("identity", "--root", root, "--tag", "v1.2.3").status,
    ).toBe(0);
    expect(
      runContract("hosted", "--payload", payload, "--sha", SHA).status,
    ).toBe(0);
    expect(
      runContract(
        "artifact",
        "--root",
        root,
        "--archive",
        archive,
        "--tag",
        "v1.2.3",
      ).status,
    ).toBe(0);
    expect(
      runContract("checksum", "--archive", archive, "--output", checksum)
        .status,
    ).toBe(0);
    expect(readFileSync(checksum, "utf8")).toMatch(
      /^[0-9a-f]{64} {2}gainratio-privacy-core-1\.2\.3\.tgz\n$/,
    );
  });

  it("rejects each source identity mismatch", () => {
    const wrongName = sourceFixture();
    writeFileSync(
      join(wrongName, "package.json"),
      JSON.stringify({ name: "privacy-core", version: "1.2.3" }),
    );
    expectRejected("identity", "--root", wrongName, "--tag", "v1.2.3");

    const wrongTag = sourceFixture();
    expectRejected("identity", "--root", wrongTag, "--tag", "v1.2.4");

    const missingChangelog = sourceFixture();
    writeFileSync(
      join(missingChangelog, "CHANGELOG.md"),
      "# Changelog\n\n## [Unreleased]\n\n## [1.2.2] — 2026-08-25\n",
    );
    expectRejected("identity", "--root", missingChangelog, "--tag", "v1.2.3");
  });

  it("rejects stale, failed, or ambiguous hosted identity", () => {
    const root = sourceFixture();
    const payload = join(root, "hosted.json");
    const cases = [
      { mainSha: "b".repeat(40), tagSha: SHA, checks: [] },
      { mainSha: SHA, tagSha: "b".repeat(40), checks: [] },
      {
        mainSha: SHA,
        tagSha: SHA,
        checks: [{ name: "Dagger", headSha: SHA, conclusion: "failure" }],
      },
      {
        mainSha: SHA,
        tagSha: SHA,
        checks: [
          { name: "Dagger", headSha: SHA, conclusion: "success" },
          { name: "Dagger", headSha: SHA, conclusion: "success" },
        ],
      },
    ];
    for (const payloadCase of cases) {
      writeFileSync(payload, JSON.stringify(payloadCase));
      expectRejected("hosted", "--payload", payload, "--sha", SHA);
    }
  });

  it("requires an ephemeral OIDC-ingress token for hosted lookup", () => {
    const result = runContract(
      "github",
      "--repository",
      "hseshadr/privacy-core",
      "--sha",
      SHA,
      "--tag",
      "v1.2.3",
    );

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("GITHUB_TOKEN");
  });

  it("rejects an artifact whose package identity or exports drift", () => {
    const wrongVersionRoot = sourceFixture();
    const wrongPackage = join(wrongVersionRoot, "package");
    mkdirSync(join(wrongPackage, "dist"), { recursive: true });
    writeFileSync(
      join(wrongPackage, "package.json"),
      JSON.stringify({
        name: "@gainratio/privacy-core",
        version: "9.9.9",
        exports: { ".": "./dist/index.js" },
      }),
    );
    writeFileSync(join(wrongPackage, "dist/index.js"), "export {};\n");
    const wrongArchive = join(
      wrongVersionRoot,
      "gainratio-privacy-core-1.2.3.tgz",
    );
    expect(
      spawnSync("tar", ["-czf", wrongArchive, "package"], {
        cwd: wrongVersionRoot,
      }).status,
    ).toBe(0);
    expectRejected(
      "artifact",
      "--root",
      wrongVersionRoot,
      "--archive",
      wrongArchive,
      "--tag",
      "v1.2.3",
    );

    const missingExportRoot = sourceFixture();
    const archive = packageFixture(missingExportRoot);
    const packageRoot = join(missingExportRoot, "package");
    writeFileSync(
      join(packageRoot, "package.json"),
      JSON.stringify({
        name: "@gainratio/privacy-core",
        version: "1.2.3",
        exports: { ".": "./dist/missing.js" },
      }),
    );
    expect(
      spawnSync("tar", ["-czf", archive, "package"], { cwd: missingExportRoot })
        .status,
    ).toBe(0);
    expectRejected(
      "artifact",
      "--root",
      missingExportRoot,
      "--archive",
      archive,
      "--tag",
      "v1.2.3",
    );
  });

  it("rejects source, test, workflow, or secret material in the tarball", () => {
    const root = sourceFixture();
    const archive = packageFixture(root);
    const packageRoot = join(root, "package");
    mkdirSync(join(packageRoot, "src"));
    writeFileSync(join(packageRoot, "src/private.ts"), "const token = 'no';\n");
    expect(
      spawnSync("tar", ["-czf", archive, "package"], { cwd: root }).status,
    ).toBe(0);

    expectRejected(
      "artifact",
      "--root",
      root,
      "--archive",
      archive,
      "--tag",
      "v1.2.3",
    );
  });
});
