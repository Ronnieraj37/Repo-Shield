# CRE Confidential Workflow

RepoShield's analysis pipeline running inside a hardware-isolated TEE, so that
the developer's GitHub token, the Gemini API key, and the contents of a private
repository are never visible to the node operator or to this application.

## Status

**Simulated successfully.** `simulation-transcript.txt` is the full run:

```
Running trigger trigger=http-trigger@1.0.0-alpha
Handler requested TEE Execution
[USER LOG] reposhield-scan-request repo=reposhield-samples/senior-web3-frontend-task
[USER LOG] reposhield-getsecrets-ok
[USER LOG] analyzing ...@5ff5b0d — 8 of 8 candidate files read
[USER LOG] verdict "danger" (100/100) from 19 findings

✓ Workflow Simulation Result:
{ "commit": "5ff5b0d…", "threatScore": 100, "verdict": "danger",
  "findingCount": 19, "criticalCount": 12, ... }
```

Reproduce it:

```bash
cd cre/reposhield && bun install
npx tsx ../mock-server.mts &          # the simulator has no internet route
cd .. && cre workflow simulate ./reposhield \
  --target staging-settings -e .env \
  --http-payload ./payload.json --trigger-index 0
```

Not deployed. Deployment needs Confidential Workflows beta access, requested
through Chainlink's form — a separate path from `cre account access`, which
grants general deployment rights and is *not* the one to use. Simulation alone
qualifies for the bounty; Chainlink staff confirmed this repeatedly during the
hackathon.

### What it took to get here

Three things, none of them obvious from the error:

- **The engine read `process.env` at module scope.** `process` does not exist
  in the CRE WASM runtime, so merely importing the analyzer threw — surfacing
  as `wasm trap: unreachable` during the subscribe phase, which points nowhere
  near the cause. Model overrides now arrive through `AnalyzeOptions`.
- **`ConfidentialHTTPClient` is the wrong client inside a TEE handler**, despite
  the name. It has no `TeeRuntime` overload; using it needed a cast that should
  have been the clue. `HTTPClient.sendRequest()` takes a `TeeRuntime` directly,
  and that is what keeps request and response payloads confidential from node
  operators.
- **The Runner takes a zod `configSchema`**, not a hand-rolled `configParser`.
  The older audit-firewall template shows the latter; the current
  hello-confidential-workflows template is the one to follow.

Isolating that meant scaffolding the official template with `cre init`,
confirming it simulated, and mutating it toward this workflow until the trap
reappeared.

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
