// The package publishes as @gainratio/privacy-core. Its own old @edgeproc name
// must not creep back into anything that decides what gets published, and
// neither may any other @edgeproc package: avow is consumed as @gainratio/avow.
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = join(import.meta.dirname, "..");
const read = (path: string): string => readFileSync(join(ROOT, path), "utf8");
const WORKFLOWS = readdirSync(join(ROOT, ".github/workflows"))
  .filter((name) => name.endsWith(".yml"))
  .map((name) => `.github/workflows/${name}`);
const OLD_FORMS = ["@edgeproc/", "edgeproc-privacy-core-"];

describe("npm scope", () => {
  it("publishes under @gainratio", () => {
    expect((JSON.parse(read("package.json")) as { name: string }).name).toBe(
      "@gainratio/privacy-core",
    );
  });

  it("names its old package name nowhere in the release surfaces", () => {
    const surfaces = [
      "package.json",
      "scripts/release-contract.ts",
      ".dagger/src/privacy_core/main.py",
      ...WORKFLOWS,
    ];
    const offenders = surfaces.filter((path) =>
      OLD_FORMS.some((form) => read(path).includes(form)),
    );
    expect(WORKFLOWS.length).toBeGreaterThan(0);
    expect(offenders).toEqual([]);
  });
});
