# CRE Confidential Workflow

RepoShield's analysis pipeline running inside a hardware-isolated TEE, so that
the developer's GitHub token, the Gemini API key, and the contents of a private
repository are never visible to the node operator or to this application.

## Status

```bash
cd cre && npm install
npm run typecheck   # compiles against @chainlink/cre-sdk@1.20.0
npm test            # executes the confidential body with mocked CRE deps
```

`npm test` runs the real `runConfidentialScan` against a fake vault and a
recorded transport, and asserts the properties that matter:

```
log: analyzing reposhield-samples/senior-web3-frontend-task@5ff5b0d — 8 of 8 files read
log: verdict "danger" (100/100) from 19 findings
PASS reads both secrets from the vault
PASS every GitHub request carries the vault token
PASS leaks no repository source in the DON payload
PASS emits only the aggregate verdict
```

**Not yet simulated or deployed.** That needs the `cre` CLI and a Chainlink
account (below). The logic is executed and verified; the enclave itself is not.

## What makes it the same engine

`src/workflow.ts` imports `analyzeRepo` from `../../lib/analyzer` — the exact
function the web app calls. That is only possible because the engine was made
portable first:

| CRE WASM restriction | How the engine avoids it |
|---|---|
| no `fetch` | analyzer takes an injected `HttpClient`; `src/http-cre.ts` backs it with the **confidential-http** capability |
| no `crypto` | `lib/analyzer/portable.ts` implements SHA-256 by hand, verified against Node |
| no `Buffer` | same file implements base64 and UTF-8 |
| no `setTimeout` | retries and backoff live in the web adapter only |

## What crosses the boundary

In: a repo name over the HTTP trigger. Inside: two vault secrets, the repo's
file tree, and its source. Out to the DON:

```json
{ "repo": "...", "commit": "...", "threatScore": 87,
  "verdict": "danger", "findingCount": 12, "criticalCount": 4, "scannedAt": "..." }
```

Findings quote repository source verbatim, so they stay in the enclave.

## What you need to do

1. **Install the CRE CLI** — a release binary from
   [smartcontractkit/cre-cli](https://github.com/smartcontractkit/cre-cli/releases)
   (`cre_darwin_arm64.zip` on Apple Silicon). Not on npm.
2. **Register the secrets in the Vault DON**: `GEMINI_API_KEY`, and a
   `GITHUB_TOKEN` for the repo being scanned.
3. **Add the project config** the CLI expects (`project.yaml` / `workflow.yaml`)
   — generate it with `cre init` rather than hand-writing it, so it matches the
   CLI version you installed.
4. **Simulate**: `cre workflow simulate .` and keep the terminal output. The
   Confidential Workflow prize track requires evidence of a successful
   simulation or deployment.

## Worth doing if there is time

The confidential-http capability accepts `vaultDonSecrets`, which lets the
*capability* substitute a secret into the outbound request. Using it would mean
the GitHub token and Gemini key never enter workflow memory at all — a stronger
claim than reading them with `getSecret`. `src/http-cre.ts` already builds the
wrapping `ConfidentialHTTPRequest`, so this is a small change.
