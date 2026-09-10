import "server-only";
import {
  createWalletClient,
  createPublicClient,
  http,
  keccak256,
  toBytes,
  type Hex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { sepolia } from "viem/chains";
import type { ThreatReport, Verdict } from "./analyzer/types";

/**
 * Writes a scan verdict to the ScanRegistry contract on Sepolia.
 *
 * This is what makes the onchain registry a real thing rather than a demo
 * prop: a completed scan can be published, and from then on The Graph can
 * answer "has anyone flagged this repo?" for everyone, permanently.
 *
 * Server-side and deliberate — a scan does not auto-publish. Publishing costs
 * gas and writes a permanent public record, so it is an explicit action from
 * the report, not a side effect of scanning.
 */

const REGISTRY_ABI = [
  {
    type: "function",
    name: "publish",
    stateMutability: "nonpayable",
    inputs: [
      { name: "repo", type: "string" },
      { name: "commit", type: "bytes32" },
      { name: "threatScore", type: "uint16" },
      { name: "verdict", type: "uint8" },
    ],
    outputs: [],
  },
] as const;

const VERDICT_CODE: Record<Verdict, number> = { safe: 1, caution: 2, danger: 3 };

export function registryConfigured(): boolean {
  return Boolean(
    process.env.REGISTRY_ADDRESS && process.env.REGISTRY_PRIVATE_KEY,
  );
}

function rpcUrl(): string {
  return process.env.SEPOLIA_RPC_URL ?? "https://ethereum-sepolia-rpc.publicnode.com";
}

export interface PublishResult {
  txHash: string;
  explorerUrl: string;
}

export async function publishToRegistry(report: ThreatReport): Promise<PublishResult> {
  const address = process.env.REGISTRY_ADDRESS as Hex | undefined;
  const privateKey = process.env.REGISTRY_PRIVATE_KEY as Hex | undefined;
  if (!address || !privateKey) {
    throw new Error("The onchain registry is not configured on this server.");
  }

  const account = privateKeyToAccount(privateKey);
  const wallet = createWalletClient({ account, chain: sepolia, transport: http(rpcUrl()) });

  const repoName = `${report.repo.owner}/${report.repo.name}`;
  // The commit SHA is 40 hex chars (20 bytes); left-pad into a bytes32.
  const commit = `0x${report.repo.commit.replace(/^0x/, "").padStart(64, "0").slice(0, 64)}` as Hex;

  const txHash = await wallet.writeContract({
    address,
    abi: REGISTRY_ABI,
    functionName: "publish",
    args: [repoName, commit, report.threatScore, VERDICT_CODE[report.verdict]],
  });

  return {
    txHash,
    explorerUrl: `https://sepolia.etherscan.io/tx/${txHash}`,
  };
}

/**
 * Read the latest verdict straight from the contract.
 *
 * A fallback for when the subgraph has not yet indexed a just-published scan —
 * the contract is the source of truth, The Graph is the queryable index of it.
 */
export async function readLatestFromChain(
  repoName: string,
): Promise<{ threatScore: number; verdict: number; scannedAt: number } | null> {
  const address = process.env.REGISTRY_ADDRESS as Hex | undefined;
  if (!address) return null;

  const client = createPublicClient({ chain: sepolia, transport: http(rpcUrl()) });
  try {
    const result = (await client.readContract({
      address,
      abi: [
        {
          type: "function",
          name: "latest",
          stateMutability: "view",
          inputs: [{ name: "", type: "bytes32" }],
          outputs: [
            { name: "commit", type: "bytes32" },
            { name: "threatScore", type: "uint16" },
            { name: "verdict", type: "uint8" },
            { name: "scannedAt", type: "uint40" },
            { name: "reporter", type: "address" },
            { name: "count", type: "uint32" },
          ],
        },
      ] as const,
      functionName: "latest",
      args: [keccak256(toBytes(repoName))],
    })) as readonly [Hex, number, number, number, Hex, number];

    if (result[3] === 0) return null; // scannedAt == 0 → never published
    return { threatScore: result[1], verdict: result[2], scannedAt: result[3] };
  } catch {
    return null;
  }
}
