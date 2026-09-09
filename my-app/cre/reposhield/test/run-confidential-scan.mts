/**
 * Executes the confidential scan body on a laptop.
 *
 * `npm run typecheck` proves the workflow compiles against the SDK. This
 * proves the code inside the enclave actually runs: secrets are read, the
 * GitHub API is driven over the injected transport, the analyzer produces a
 * report, and only the aggregate verdict is returned.
 *
 * The transport here serves a bundled malicious fixture instead of calling
 * GitHub, so the run is deterministic, offline, and free.
 *
 *   npm test
 */
import { runConfidentialScan } from "../scan";
import type { HttpClient, HttpRequest } from "../../../lib/analyzer/http";
import { getSample } from "../../../lib/samples";

const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const DIM = "\x1b[2m";
const RESET = "\x1b[0m";

const SAMPLE = getSample("contagious-interview")!;

/**
 * Stands in for confidential-http, answering GitHub's REST API from the
 * fixture. Every request is recorded so the test can assert that the token
 * actually travelled on them — that is the property the enclave exists to
 * protect.
 */
function createFixtureTransport(): HttpClient & { seen: HttpRequest[] } {
  const seen: HttpRequest[] = [];
  const files = SAMPLE.files;

  const json = (body: unknown) => ({ status: 200, body: JSON.stringify(body) });

  return {
    seen,
    async send(request: HttpRequest) {
      seen.push(request);
      const url = request.url;

      if (/\/repos\/[^/]+\/[^/]+$/.test(url)) {
        return json({
          name: SAMPLE.repo.name,
          owner: { login: SAMPLE.repo.owner },
          html_url: SAMPLE.repo.url,
          private: true,
          default_branch: "main",
          stargazers_count: 0,
          pushed_at: new Date().toISOString(),
          size: 40,
        });
      }

      if (url.includes("/commits/")) return json({ sha: SAMPLE.repo.commit });

      if (url.includes("/git/trees/")) {
        return json({
          truncated: false,
          tree: Object.entries(files).map(([path, content]) => ({
            path,
            type: "blob",
            size: content.length,
          })),
        });
      }

      if (url.includes("/contents/")) {
        const path = decodeURIComponent(
          url.split("/contents/")[1].split("?")[0],
        );
        const content: string | undefined = files[path as keyof typeof files];
        if (!content) return { status: 404, body: "{}" };
        return json({
          encoding: "base64",
          content: Buffer.from(content, "utf8").toString("base64"),
        });
      }

      // Gemini. Phase 2 is exercised separately by the web app's `test:ai`;
      // here it is stubbed so this run stays offline and deterministic.
      if (url.includes("generativelanguage")) {
        return {
          status: 503,
          body: '{"error":{"message":"stubbed offline"}}',
        };
      }

      return { status: 404, body: "{}" };
    },
  };
}

const SECRETS: Record<string, string> = {
  GITHUB_TOKEN: "gho_fake_token_for_local_execution",
  GEMINI_API_KEY: "fake-gemini-key",
};

let failures = 0;
function check(ok: boolean, message: string) {
  console.log(`  ${ok ? `${GREEN}PASS${RESET}` : `${RED}FAIL${RESET}`} ${message}`);
  if (!ok) failures++;
}

async function main() {
  console.log("\nExecuting the confidential scan body with mocked CRE deps\n");

  const http = createFixtureTransport();
  const logs: string[] = [];
  const requested: string[] = [];

  const verdict = await runConfidentialScan(
    { repo: `${SAMPLE.repo.owner}/${SAMPLE.repo.name}` },
    {
      getSecret: (id: string) => {
        requested.push(id);
        const value = SECRETS[id];
        if (!value) throw new Error(`no such secret: ${id}`);
        return value;
      },
      http,
      log: (m: string) => logs.push(m),
    },
  );

  for (const line of logs) console.log(`  ${DIM}log: ${line}${RESET}`);
  console.log(`  ${DIM}returned: ${JSON.stringify(verdict)}${RESET}\n`);

  check(
    requested.includes("GITHUB_TOKEN") && requested.includes("GEMINI_API_KEY"),
    "reads both secrets from the vault",
  );
  check(http.seen.length > 3, `drives GitHub over the injected transport (${http.seen.length} requests)`);
  check(
    http.seen
      .filter((r: HttpRequest) => r.url.includes("api.github.com"))
      .every(
        (r: HttpRequest) =>
          r.headers?.authorization === `Bearer ${SECRETS.GITHUB_TOKEN}`,
      ),
    "every GitHub request carries the vault token",
  );
  check(verdict.verdict === "danger", `reaches the right verdict ("${verdict.verdict}")`);
  check(verdict.threatScore >= 61, `scores it as dangerous (${verdict.threatScore}/100)`);
  check(verdict.criticalCount > 0, `counts critical findings (${verdict.criticalCount})`);
  check(verdict.commit === SAMPLE.repo.commit, "pins the commit it analysed");

  // The point of the whole arrangement: source code must not ride out on the
  // return value, because that value is what reaches the DON.
  const emitted = JSON.stringify(verdict);
  check(
    !emitted.includes("id_rsa") &&
      !emitted.includes("homedir") &&
      !emitted.includes(".vscode/prepare.js"),
    "leaks no repository source in the DON payload",
  );
  check(
    Object.keys(verdict).length === 7,
    `emits only the aggregate verdict (${Object.keys(verdict).join(", ")})`,
  );

  console.log(
    failures === 0
      ? `\n${GREEN}Confidential scan body executed correctly.${RESET}\n`
      : `\n${RED}${failures} check(s) failed.${RESET}\n`,
  );
  if (failures > 0) process.exit(1);
}

main();
