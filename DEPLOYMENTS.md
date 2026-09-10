# Live Deployments

## App

**https://repo-shield.vercel.app** — Next.js on Vercel. Public repos scan with no
sign-in; private repos via GitHub OAuth or a pasted token.

## The Graph — onchain scan registry

| | |
|---|---|
| **ScanRegistry** | [`0x1781F29D464A8EAa7f21bA14C6c778Cc626c4277`](https://sepolia.etherscan.io/address/0x1781F29D464A8EAa7f21bA14C6c778Cc626c4277) |
| Network | Ethereum Sepolia |
| Deploy block | 11673613 |
| **Subgraph (Studio)** | https://thegraph.com/studio/subgraph/repo-shield |
| Query endpoint | `https://api.studio.thegraph.com/query/1760054/repo-shield/v0.0.1` |

Verified end to end: the app writes `publish()` to the contract, the
`ScanPublished` event is indexed by the subgraph, and the app reads it back
through The Graph — the `/registry` page and every report's community panel are
live queries, and the LLM consumes the same data as a decision input.

Source: [`contracts/`](contracts) (Foundry, 5/5 tests) · [`subgraph/`](subgraph).

## Chainlink CRE — Confidential Workflow

Simulated end to end with the CRE CLI (`cre workflow simulate`). Not deployed —
deployment needs Confidential Workflows beta access; **simulation alone
qualifies for the bounty** (confirmed by Chainlink staff during the hackathon).

| | |
|---|---|
| Workflow | [`my-app/cre/reposhield/`](my-app/cre/reposhield) |
| SDK / CLI | `@chainlink/cre-sdk@1.20.0` · `cre` CLI `v1.33.0` |
| WASM binary hash | `c7b3bd6adfa00f63d23f643e67a87814f4e75eb2e98acc0e472326b82766bf2e` |
| Transcript | [`my-app/cre/simulation-transcript.txt`](my-app/cre/simulation-transcript.txt) |

The simulation reads two secrets from the vault inside the enclave, fetches a
repository over the TEE HTTP capability, analyses it, and returns only the
aggregate verdict — the full findings never leave the enclave.

## Environment variables

See [`my-app/.env.example`](my-app/.env.example). For production, set the same
values in Vercel → Settings → Environment Variables (leave `NEXT_PUBLIC_APP_URL`
unset — the app derives its origin from the request).
