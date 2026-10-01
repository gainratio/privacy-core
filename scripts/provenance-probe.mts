/**
 * Provenance probe — runs inside the Dagger publisher container (the pinned
 * node image, its bundled npm) with exactly the environment `publish` gives it.
 *
 * `npm publish --dry-run --provenance` cannot prove anything here: in npm 11 a
 * dry run returns before libnpmpublish, so provenance is never attempted and
 * the `provider: null` failure could not show up either way. Instead this runs
 * a REAL `npm publish --provenance` of a throwaway package against a loopback
 * stub registry that also stands in for the GitHub OIDC token endpoint:
 *
 * 1. With the publisher's environment, npm must get PAST provider detection —
 *    no `Automatic provenance generation not supported for provider: null` —
 *    and start provenance generation, observable as sigstore asking the OIDC
 *    endpoint for an `audience=sigstore` token. The stub hands out no token,
 *    so signing (and the upload) cannot happen and nothing leaves loopback.
 * 2. With the GitHub Actions variables stripped, the same command must fail
 *    with exactly that `provider: null` error — proving the probe tells the
 *    two apart.
 *
 * It does NOT prove a real OIDC exchange, Fulcio certificate or Rekor entry;
 * those only exist inside a real GitHub Actions run.
 */
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";

const PORT = Number(process.env.PROBE_PORT ?? "47291");
const REGISTRY = `http://127.0.0.1:${PORT}/`;
const NPM_CLI =
  process.env.PROBE_NPM_CLI ?? "/usr/local/lib/node_modules/npm/bin/npm-cli.js";
const PROVIDER_NULL =
  "Automatic provenance generation not supported for provider: null";

interface Outcome {
  readonly code: number | null;
  readonly output: string;
  readonly requests: readonly string[];
}

function fail(message: string): never {
  throw new Error(`provenance probe: ${message}`);
}

function stub(requests: string[]): Server {
  return createServer((request: IncomingMessage, response) => {
    requests.push(`${request.method ?? "?"} ${request.url ?? "?"}`);
    request.resume();
    // The OIDC endpoint answers without a token; the registry knows no
    // packages and refuses every write.
    const status = request.url?.startsWith("/token")
      ? 200
      : request.method === "GET"
        ? 404
        : 500;
    response.writeHead(status, { "content-type": "application/json" });
    response.end("{}");
  });
}

function throwawayPackage(): string {
  const root = mkdtempSync(join(tmpdir(), "provenance-probe-"));
  const dir = join(root, "package");
  mkdirSync(dir);
  writeFileSync(
    join(dir, "package.json"),
    JSON.stringify({
      name: "@gainratio/provenance-probe",
      version: "0.0.0",
      repository: {
        type: "git",
        url: "git+https://github.com/hseshadr/privacy-core.git",
      },
    }),
  );
  writeFileSync(join(dir, "index.js"), "export {};\n");
  return dir;
}

function withoutGitHubActions(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  return Object.fromEntries(
    Object.entries(env).filter(
      ([name]) =>
        name !== "CI" &&
        !name.startsWith("GITHUB_") &&
        !name.startsWith("RUNNER_"),
    ),
  );
}

function publish(dir: string, env: NodeJS.ProcessEnv): Promise<Outcome> {
  const requests: string[] = [];
  const server = stub(requests);
  const cache = mkdtempSync(join(tmpdir(), "provenance-probe-cache-"));
  const args = [
    NPM_CLI,
    "publish",
    // Absolute (under tmpdir), so npm can never read it as an owner/repo spec.
    dir,
    "--provenance",
    "--access",
    "public",
    "--ignore-scripts",
    `--registry=${REGISTRY}`,
    `--//127.0.0.1:${PORT}/:_authToken=probe-not-a-token`,
    `--cache=${cache}`,
    "--fetch-retries=0",
    "--update-notifier=false",
  ];
  return new Promise((resolve, reject) => {
    server.listen(PORT, "127.0.0.1", () => {
      const child = spawn(process.execPath, args, { env });
      let output = "";
      child.stdout.on("data", (chunk: Buffer) => {
        output += chunk.toString();
      });
      child.stderr.on("data", (chunk: Buffer) => {
        output += chunk.toString();
      });
      child.on("error", reject);
      child.on("close", (code) => {
        server.close();
        resolve({ code, output, requests });
      });
    });
  });
}

const dir = throwawayPackage();
if (!readdirSync(dir).includes("package.json")) fail("no package to publish");

const github = await publish(dir, process.env);
if (github.output.includes(PROVIDER_NULL)) {
  fail(`npm still sees no CI provider:\n${github.output}`);
}
if (!github.requests.some((r) => r.includes("audience=sigstore"))) {
  fail(
    `npm never started provenance generation (requests: ${github.requests.join(", ")}):\n${github.output}`,
  );
}
if (github.requests.some((r) => r.startsWith("PUT "))) {
  fail("npm uploaded without a provenance signature");
}
if (github.code === 0) fail("publish succeeded against the stub");

const bare = await publish(dir, withoutGitHubActions(process.env));
if (!bare.output.includes(PROVIDER_NULL)) {
  fail(`control run did not fail on provider detection:\n${bare.output}`);
}

process.stdout.write(
  `${JSON.stringify({
    githubActions: {
      providerDetected: true,
      provenanceStarted: true,
      requests: github.requests,
    },
    control: { providerNull: true },
  })}\n`,
);
