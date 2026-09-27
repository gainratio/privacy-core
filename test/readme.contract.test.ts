import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * The README contract. It pins the plain-English shape (title, one-line
 * description, install line, sections in order), the facts the README
 * promises (the real example output, the name that is NOT caught, the
 * published version it documents), links to the developer docs, and a
 * banned-jargon list. String and regex checks only; it does not judge prose.
 */
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const readme = readFileSync(join(root, "README.md"), "utf8");
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as {
  description: string;
  version: string;
};

const at = (heading: string): number => {
  const index = readme.indexOf(`\n${heading}\n`);
  expect(index, heading).toBeGreaterThan(-1);
  return index;
};

const section = (heading: string): string => {
  const start = at(heading) + heading.length + 2;
  const next = readme.indexOf("\n## ", start);
  return readme.slice(start, next === -1 ? undefined : next);
};

/** README prose with fenced code blocks and inline code removed. */
const prose = readme
  .replace(/```[\s\S]*?```/g, "")
  .replace(/`[^`\n]*`/g, "")
  .replace(/\]\([^)]*\)/g, "]");

const SECTION_ORDER = [
  "## Try it",
  "## How it works",
  "## What it does not do",
  "## When to use something else",
  "## Install",
  "## Develop",
  "## More detail",
  "## License",
];

const BANNED = [
  /\bnorthstar\b/i,
  /\bseam\b/i,
  /\blego\b/i,
  /trust envelope/i,
  /fail[- ]closed/i,
  /\bgate\b/i,
  /\bfleet\b/i,
  /\bportfolio\b/i,
  /production[- ]ready/i,
  /\brobust\b/i,
  /\bblazing\b/i,
  /enterprise[- ]grade/i,
  /\bseamless/i,
  /\begress\b/i,
  /\brehydrat/i,
  /At a glance/,
  /Try it in 60 seconds/,
];

describe("README contract", () => {
  const lines = readme.split("\n");

  it("opens with the package name, then one plain sentence equal to the package description", () => {
    expect(lines[0]).toBe("# @edgeproc/privacy-core");
    const tagline = lines
      .slice(1)
      .find((line) => line.trim() !== "" && !line.startsWith("[!["));
    expect(tagline).toBe(pkg.description);
    expect(pkg.description.length).toBeLessThanOrEqual(120);
    expect(pkg.description).toMatch(/card numbers/);
    expect(pkg.description).toMatch(/AI/);
  });

  it("puts the one-line install, in bold, right under the description", () => {
    const after = readme.slice(readme.indexOf(pkg.description));
    const next = after
      .split("\n")
      .slice(1)
      .find((line) => line.trim() !== "");
    expect(next).toContain("**`npm install @edgeproc/privacy-core`**");
  });

  it("keeps at most three badges (CI, version, license)", () => {
    expect(readme.split("[![").length - 1).toBeLessThanOrEqual(3);
  });

  it("links the technical docs, including Getting started, before Try it", () => {
    const line = lines.find((l) => l.startsWith("**Technical docs:**"));
    expect(line).toBeDefined();
    expect(line).toContain("(docs/ARCHITECTURE.md)");
    expect(line).toContain("(docs/GETTING_STARTED.md)");
    expect(readme.indexOf("**Technical docs:**")).toBeLessThan(at("## Try it"));
  });

  it("has the standard sections, in order", () => {
    const positions = SECTION_ORDER.map(at);
    expect(positions).toEqual([...positions].sort((a, b) => a - b));
  });

  it("shows the real output of the example, including the name it misses", () => {
    const tryIt = section("## Try it");
    expect(tryIt).toContain(
      "will send:  Maria Lopez asked: refund [AMOUNT_1] to card [CARD_1] and email [EMAIL_1].",
    );
    expect(tryIt).toContain(
      "you see:    I reviewed your statement. It referenced 3 redacted value(s): $482.10, 4242 4242 4242 4242, maria@example.com.",
    );
    expect(tryIt).toMatch(/name is not caught/i);
    expect(tryIt).toContain("(docs/assets/demo.png)");
    expect(existsSync(join(root, "docs/assets/demo.png"))).toBe(true);
  });

  it("says which published version the example was run against", () => {
    expect(section("## Try it")).toContain(`version ${pkg.version}`);
  });

  it("states the honest limits", () => {
    const limits = section("## What it does not do");
    for (const fact of [/names/i, /anonymous/i, /memory/i, /512 KiB/]) {
      expect(limits).toMatch(fact);
    }
  });

  it("links Getting started from Develop and runs the same check as CI", () => {
    const develop = section("## Develop");
    expect(develop).toContain("(docs/GETTING_STARTED.md)");
    expect(develop).toContain("pnpm gate");
    expect(existsSync(join(root, "docs/GETTING_STARTED.md"))).toBe(true);
  });

  it("says MIT under License", () => {
    expect(section("## License")).toMatch(/\bMIT\b/);
  });

  it("uses no internal jargon or hype in its prose", () => {
    for (const word of BANNED) {
      expect(prose, String(word)).not.toMatch(word);
    }
  });

  it("resolves every relative link to a file in the repo", () => {
    const targets = [...readme.matchAll(/\]\(([^)\s]+)\)/g)].map(
      (match) => match[1] ?? "",
    );
    const relative = targets.filter(
      (target) => !/^(?:[a-z]+:|#)/i.test(target),
    );
    expect(relative.length).toBeGreaterThan(0);
    for (const target of relative) {
      const path = target.split("#")[0] ?? "";
      expect(existsSync(join(root, path)), target).toBe(true);
    }
  });
});
