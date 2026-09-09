/**
 * Local stand-in for GitHub and Gemini, for `cre workflow simulate`.
 *
 * The CRE simulator has no route to the public internet, so the official
 * templates ship a mock server and point the workflow config at it. This one
 * serves a bundled malicious fixture through GitHub's real REST shapes, so the
 * workflow exercises its genuine resolve → tree → fetch-blobs → analyse path
 * rather than a shortcut.
 *
 *   npx tsx cre/mock-server.mts
 */
import { createServer, type ServerResponse } from "node:http";
import { getSample } from "../lib/samples";

const SAMPLE = getSample("contagious-interview")!;
const FILES = SAMPLE.files;
const OWNER = SAMPLE.repo.owner;
const NAME = SAMPLE.repo.name;
const COMMIT = SAMPLE.repo.commit;

console.log(
  `[mock] serving ${Object.keys(FILES).length} fixture files as ${OWNER}/${NAME}`,
);

function json(res: ServerResponse, body: unknown, status = 200) {
  res.writeHead(status, {
    "content-type": "application/json",
    "x-ratelimit-remaining": "4999",
  });
  res.end(JSON.stringify(body));
}

createServer((req, res) => {
  let raw = "";
  req.on("data", (c) => (raw += c));
  req.on("end", () => {
    const url = req.url ?? "";

    // ---- GitHub -----------------------------------------------------------
    if (url.startsWith("/github")) {
      const auth = String(req.headers.authorization ?? "(none)");
      console.log(`[mock:github] ${req.method} ${url}  auth=${auth.slice(0, 20)}…`);

      if (/\/repos\/[^/]+\/[^/]+$/.test(url)) {
        return json(res, {
          name: NAME,
          owner: { login: OWNER },
          html_url: `https://github.com/${OWNER}/${NAME}`,
          private: true,
          default_branch: "main",
          stargazers_count: 0,
          pushed_at: new Date().toISOString(),
          size: 40,
        });
      }
      if (url.includes("/commits/")) return json(res, { sha: COMMIT });
      if (url.includes("/git/trees/")) {
        return json(res, {
          truncated: false,
          tree: Object.entries(FILES).map(([path, content]) => ({
            path,
            type: "blob",
            size: Buffer.byteLength(content, "utf8"),
          })),
        });
      }
      if (url.includes("/contents/")) {
        const path = decodeURIComponent(url.split("/contents/")[1].split("?")[0]);
        const content = FILES[path as keyof typeof FILES];
        if (content === undefined) return json(res, { message: "Not Found" }, 404);
        return json(res, {
          encoding: "base64",
          content: Buffer.from(content, "utf8").toString("base64"),
        });
      }
      if (url.includes("/rate_limit")) {
        return json(res, {
          resources: { core: { remaining: 4999, limit: 5000, reset: 0 } },
        });
      }
      return json(res, { message: "Not Found" }, 404);
    }

    // ---- Gemini -----------------------------------------------------------
    if (url.startsWith("/gemini")) {
      const key = String(req.headers["x-goog-api-key"] ?? "(none)");
      console.log(
        `[mock:gemini] ${req.method} ${url}  key=${key.slice(0, 12)}…  ` +
          `${raw.length} bytes of repository code sent from the enclave`,
      );
      // A fixed, plausible response. The simulation exists to prove the
      // enclave drives the pipeline and controls what leaves it — not to
      // re-test Gemini, which `yarn test:ai` does against the live API.
      return json(res, {
        candidates: [
          {
            finishReason: "STOP",
            content: {
              parts: [
                {
                  text: JSON.stringify({
                    isMalicious: true,
                    summary:
                      "The repository auto-executes a script when the folder is opened in VS Code. That script reads SSH keys, AWS credentials, Solana keypairs and browser wallet extension storage, and posts them to an external host.",
                    findings: [
                      {
                        file: ".vscode/prepare.js",
                        severity: "critical",
                        title: "Credential harvesting on folder open",
                        executionFlow:
                          "VS Code runs this file the moment the project is opened. It reads ~/.ssh/id_rsa, ~/.aws/credentials, ~/.config/solana/id.json and the MetaMask extension store, bundles them with the full process environment, and POSTs the lot to cdn-assets-delivery.invalid.",
                        evidence: "fs.readFileSync(path.join(os.homedir(), '.ssh', 'id_rsa'))",
                        recommendation:
                          "Do not open this folder in an editor. If you already did, rotate every key on the machine.",
                      },
                    ],
                  }),
                },
              ],
            },
          },
        ],
      });
    }

    json(res, { message: "Not Found" }, 404);
  });
}).listen(8787, "127.0.0.1", () =>
  console.log("[mock] listening on http://127.0.0.1:8787"),
);
