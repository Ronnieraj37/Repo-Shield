# RepoShield Contracts

`ScanRegistry` — a public, append-only registry of RepoShield scan verdicts on
Sepolia. Verdicts are published here and indexed by the [subgraph](../subgraph)
so The Graph can answer "has anyone flagged this repo?".

## Setup

```bash
forge install foundry-rs/forge-std   # vendored dep, not committed
forge test
```

## Deploy to Sepolia

```bash
cp .env.example .env      # set DEPLOYER_PRIVATE_KEY (a funded testnet key)
forge script script/Deploy.s.sol \
  --rpc-url "$SEPOLIA_RPC_URL" --broadcast
```

The deploy prints the contract address. Put it in the web app's
`REGISTRY_ADDRESS`, and give the subgraph its address + deploy block.
