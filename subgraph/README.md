# RepoShield Registry Subgraph

Indexes the `ScanPublished` events from the [`ScanRegistry`](../contracts/src/ScanRegistry.sol)
contract on Sepolia, so the RepoShield app can ask The Graph:

- has anyone flagged `owner/repo` before?
- what has the community flagged recently?

Both questions are about what *other* people found — which a single scan
cannot answer. That read is the load-bearing use of The Graph in the project.

## Entities

- `Repo` — latest verdict per repository (mutable)
- `Publication` — every publish, forever (immutable feed)
- `Registry` — headline totals (`id: "global"`)

## Deploy (after the contract is live)

```bash
bun install
node set-address.mjs <CONTRACT_ADDRESS> <DEPLOY_BLOCK>   # from `forge create`
bun run codegen && bun run build

# authenticate once with the deploy key from Subgraph Studio, then publish
graph auth <STUDIO_DEPLOY_KEY>
graph deploy reposhield-registry
```

Studio prints a **query URL**. Put it in the web app's `GRAPH_SUBGRAPH_URL`.
