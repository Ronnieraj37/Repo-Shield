# Environment variables — where each comes from

**Local dev (`my-app/.env.local`) is already fully configured** — every value
below is set on this machine. This file is the reference for **Vercel**
(production), which currently has only the original GitHub/session/Gemini vars.

Add these in Vercel → Project → Settings → Environment Variables.

## Required (the app runs on these)

| Variable | Where to get it | Secret? |
|---|---|---|
| `SESSION_SECRET` | Generate fresh for prod: `openssl rand -hex 32` | 🔒 |
| `GITHUB_CLIENT_ID` | Your GitHub OAuth App (github.com/settings/developers) | public |
| `GITHUB_CLIENT_SECRET` | Same OAuth App → "Generate a new client secret" | 🔒 |
| `GITHUB_TOKEN` | github.com/settings/tokens → classic, **no scopes** (raises rate limit) | 🔒 |
| `GEMINI_API_KEY` | aistudio.google.com/apikey | 🔒 |
| `NEXT_PUBLIC_APP_URL` | Leave **unset** in prod — the app derives it from the request | — |

> OAuth callback for prod: add `https://repo-shield.vercel.app/api/auth/github/callback`
> to the OAuth App's Authorization callback URLs.

## The Graph registry (live now)

| Variable | Value / source | Secret? |
|---|---|---|
| `GRAPH_SUBGRAPH_URL` | `https://api.studio.thegraph.com/query/1760054/repo-shield/v0.0.1` | public |
| `GRAPH_API_KEY` | Subgraph Studio → API Keys (the `df5e…` key you made) | 🔒 |
| `REGISTRY_ADDRESS` | `0x1781F29D464A8EAa7f21bA14C6c778Cc626c4277` | public |
| `REGISTRY_PRIVATE_KEY` | The funded deployer key (in `contracts/.env`) | 🔒 |
| `SEPOLIA_RPC_URL` | `https://ethereum-sepolia-rpc.publicnode.com` | public |

## Chainlink CRE (only after you deploy the workflow — needs beta access)

| Variable | Where to get it | Secret? |
|---|---|---|
| `CRE_GATEWAY_URL` | `https://01.gateway.zone-a.cre.chain.link` (public registry) | public |
| `CRE_WORKFLOW_ID` | printed by `cre workflow deploy` (64 hex chars) | public |
| `CRE_SIGNER_PRIVATE_KEY` | a throwaway EVM key; its address must be in the workflow's authorizedKeys | 🔒 |

Until these three are set, "Confidential scan" simply doesn't appear — the app
runs everything else normally. Not a blocker for the bounty (simulation qualifies).
