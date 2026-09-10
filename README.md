# 🛡️ RepoShield

**Paste an unfamiliar GitHub repository and find out whether it's safe to run — before you run it.**

🔗 **Live app:** https://repo-shield.vercel.app

---

## The problem

Fake recruiters send developers "take-home assignments" as GitHub repositories. Opening the folder in VS Code, or running `npm install`, is enough to hand over your SSH keys, cloud credentials, and crypto wallets. The repo reads as completely normal. This is the **Contagious Interview** campaign — a real, active operation attributed to the North Korean Lazarus Group, delivering the BeaverTail / InvisibleFerret malware.

Every existing supply-chain scanner (Socket, Snyk, …) is built for the repository **owner** — it needs a GitHub App or a CI action installed. But when a "recruiter" invites you to a **private** repo as an outside collaborator, you have read access and nothing else. You can't install anything. Public scanners can't see it. Your only options are to clone it blindly or walk away.

**RepoShield is the third option** — the first candidate-side scanner. It reads what a repo *executes* — install hooks, editor tasks, build scripts, CI, obfuscated payloads — and tells you in plain English, without you ever running it.

## What it does

- **Two-phase analysis** — 38 static heuristics find the handful of files that matter, then Gemini reads only those and explains the execution flow. Fast, cheap, and it catches novel obfuscation the rules miss.
- **Judges a file by what it *can* do** — Solidity can't touch your disk, so host-threat rules never fire on `.sol`; vendored `node_modules` and forge-std are recognised and down-weighted. This is why it scores a normal Foundry repo `0/100` where a naïve scanner screams.
- **A safe-clone action plan** — every report ends with the exact commands to inspect the repo without executing it.
- **Local-first** — reports live in your browser, never on our servers.

## 🏆 Sponsor integrations

### Chainlink CRE — Confidential Workflows
The whole analysis can run inside a **hardware-isolated TEE**. Reading a private repo means holding a token that can read *all* your private repos, and shipping someone's source to an LLM — so RepoShield does both inside a Chainlink CRE `handlerInTee`. The GitHub token and Gemini key are fetched from the Vault DON *inside the enclave*; the node operator and our own servers never see them. Only a 7-field verdict crosses back to the DON — the findings quote source code, so they stay in the enclave.

The **same `analyzeRepo` engine** runs in the browser and in the TEE — which required making it free of `fetch`, `crypto`, `Buffer` and `setTimeout` (all banned in the CRE WASM runtime). It compiles to a WASM binary (`cre-sdk@1.20.0`) and **simulates end-to-end** — see [`my-app/cre/simulation-transcript.txt`](my-app/cre/simulation-transcript.txt).

### The Graph — onchain community registry
A scan tells you what *your* machine found now. The Graph tells you what *everyone else* found — permanently. RepoShield publishes verdicts to a `ScanRegistry` contract on Sepolia, indexed by a subgraph, and the **LLM reads that subgraph as a decision input**: before judging a repo it asks The Graph "has this repo — or its *owner* — been flagged before?". An owner with several flagged repos is the signature of a fake-recruitment operator (one repo per candidate), and it raises the verdict on its own — a signal no single-repo scan can see.

## 🌐 Live deployments

| | |
|---|---|
| **App** | https://repo-shield.vercel.app |
| **ScanRegistry** (Sepolia) | [`0x1781F29D464A8EAa7f21bA14C6c778Cc626c4277`](https://sepolia.etherscan.io/address/0x1781F29D464A8EAa7f21bA14C6c778Cc626c4277) |
| **Subgraph** | https://thegraph.com/studio/subgraph/repo-shield |
| **CRE workflow** | simulated (WASM `c7b3bd6a…`) — transcript in repo |

Full details in [DEPLOYMENTS.md](DEPLOYMENTS.md).

## How it works

```
Paste a repo ─▶ fetch as one archive (unmetered)
              │
              ├─▶ Phase 1: 38 static rules over manifests, editor/CI config,
              │            lockfiles, scripts — flags the risky files
              │
              ├─▶ The Graph: has this repo / owner been flagged before?
              │
              ├─▶ Phase 2: Gemini reads only the flagged files + the community
              │            evidence, and explains what they actually do
              │
              └─▶ threat score (0-100) · verdict · per-file findings · fix plan

  (all of the above can run inside a Chainlink CRE enclave)
```

## Repo layout

```
my-app/          Next.js app — the scanner, UI, and API
  lib/analyzer/    the engine: 38 rules, classifier, two-phase pipeline (pure, TEE-safe)
  cre/             Chainlink CRE confidential workflow (+ simulation transcript)
  lib/graph.ts     reads the community registry from The Graph
  lib/registry.ts  writes verdicts onchain
contracts/       ScanRegistry.sol (Foundry, 5/5 tests)
subgraph/        indexes ScanPublished → queryable by The Graph
```

## Run it

```bash
cd my-app
yarn install
cp .env.example .env.local     # SESSION_SECRET is the only required value
yarn dev                       # http://localhost:3000
```

Public repos scan with no sign-in. Click **"Fake interview assignment"** on the landing page to see a real attack scored 100/100 with no setup.

```bash
yarn test:analyzer   # rules vs. malicious + benign fixtures
yarn test:evasion    # a payload must be caught wherever it hides
yarn backtest        # 11 real repos must all score "safe"
```

## Honest limitations

RepoShield reports **evidence about what a repository contains** — it cannot prove code is safe. A clean report means nothing matched the patterns we know about, not that there's nothing there. Read the code before you run it.
