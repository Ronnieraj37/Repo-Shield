# Live Deployments

## The Graph — onchain scan registry

| | |
|---|---|
| **ScanRegistry contract** | [`0x1781F29D464A8EAa7f21bA14C6c778Cc626c4277`](https://sepolia.etherscan.io/address/0x1781F29D464A8EAa7f21bA14C6c778Cc626c4277) (Sepolia) |
| Deploy block | 11673613 |
| **Subgraph** | `repo-shield` on Subgraph Studio |
| Query endpoint | `https://api.studio.thegraph.com/query/1760054/repo-shield/v0.0.1` |
| Studio | https://thegraph.com/studio/subgraph/repo-shield |

Verified end to end: an app POST writes `publish()` to the contract, the event
is indexed by the subgraph, and the app reads it back through The Graph — the
`/registry` page and every report's community panel are live queries against
that endpoint.

Wire it into the web app (`.env.local`, and Vercel for production):

```
GRAPH_SUBGRAPH_URL=https://api.studio.thegraph.com/query/1760054/repo-shield/v0.0.1
GRAPH_API_KEY=<Subgraph Studio API key>
REGISTRY_ADDRESS=0x1781F29D464A8EAa7f21bA14C6c778Cc626c4277
REGISTRY_PRIVATE_KEY=<funded Sepolia key that publishes>
SEPOLIA_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com
```

## Chainlink CRE

Confidential workflow — simulated (see `my-app/cre/simulation-transcript.txt`).
Not deployed; deployment needs Confidential Workflows beta access.
