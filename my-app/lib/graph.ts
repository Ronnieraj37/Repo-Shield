import "server-only";
import { keccak256, toBytes } from "viem";
import type { PriorFlags } from "./analyzer/types";

/**
 * Reads from the RepoShield registry subgraph on The Graph.
 *
 * This is the load-bearing use of The Graph: the app asks the subgraph "has
 * anyone flagged this repository before?" and "what has the community flagged
 * recently?" — questions that a single scan cannot answer, because they are
 * about what *other* people found, on other machines, at other times.
 *
 * The subgraph indexes the `ScanPublished` events from the ScanRegistry
 * contract on Sepolia, so every answer here is live onchain data served
 * through a Graph provider (Subgraph Studio).
 */

export interface RegistryEntry {
  name: string;
  commit: string;
  threatScore: number;
  verdict: "Safe" | "Caution" | "Danger" | "Unknown";
  reporter: string;
  scannedAt: number;
  publishCount: number;
}

export interface RegistryStats {
  totalPublications: number;
  dangerCount: number;
  repoCount: number;
}

export function graphConfigured(): boolean {
  return Boolean(process.env.GRAPH_SUBGRAPH_URL);
}

async function query<T>(body: string): Promise<T | null> {
  const url = process.env.GRAPH_SUBGRAPH_URL;
  if (!url) return null;

  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        // The gateway takes the API key as a bearer token; the Studio dev
        // endpoint ignores it. Sending it either way is harmless.
        ...(process.env.GRAPH_API_KEY
          ? { authorization: `Bearer ${process.env.GRAPH_API_KEY}` }
          : {}),
      },
      body,
      cache: "no-store",
    });
    if (!response.ok) return null;
    const json = (await response.json()) as { data?: T; errors?: unknown };
    if (json.errors || !json.data) return null;
    return json.data;
  } catch {
    // The registry is an enhancement, never a dependency. A failed query
    // degrades to "no community data", it never fails a scan.
    return null;
  }
}

/** The current community verdict for a repository, or null if never flagged. */
export async function lookupRepo(repoName: string): Promise<RegistryEntry | null> {
  const id = repoIdHex(repoName);
  const data = await query<{ repo: RawRepo | null }>(
    JSON.stringify({
      query: `query($id: ID!) { repo(id: $id) {
        name commit threatScore verdict reporter scannedAt publishCount
      } }`,
      variables: { id },
    }),
  );
  return data?.repo ? normalize(data.repo) : null;
}

/** Recently flagged repositories, most dangerous and most recent first. */
export async function recentDangerous(limit = 20): Promise<RegistryEntry[]> {
  const data = await query<{ repos: RawRepo[] }>(
    JSON.stringify({
      query: `query($limit: Int!) {
        repos(
          first: $limit
          orderBy: scannedAt
          orderDirection: desc
          where: { verdict_in: ["Danger", "Caution"] }
        ) { name commit threatScore verdict reporter scannedAt publishCount }
      }`,
      variables: { limit },
    }),
  );
  return (data?.repos ?? []).map(normalize);
}

/**
 * All flagged repositories belonging to one owner/org.
 *
 * This is the "flag the sender, not just the repo" signal. A single flagged
 * repo can be a false alarm; an *owner* with several repos flagged dangerous
 * by different people is the shape of a Contagious Interview operator, who
 * spins up a repo per candidate under one throwaway account or org.
 */
export async function lookupOwner(owner: string, limit = 10): Promise<RegistryEntry[]> {
  const data = await query<{ repos: RawRepo[] }>(
    JSON.stringify({
      query: `query($prefix: String!, $limit: Int!) {
        repos(
          first: $limit
          orderBy: scannedAt
          orderDirection: desc
          where: { name_starts_with: $prefix, verdict_in: ["Danger", "Caution"] }
        ) { name commit threatScore verdict reporter scannedAt publishCount }
      }`,
      variables: { prefix: `${owner}/`, limit },
    }),
  );
  return (data?.repos ?? []).map(normalize);
}

export async function registryStats(): Promise<RegistryStats | null> {
  const data = await query<{ registry: RawStats | null }>(
    JSON.stringify({
      query: `{ registry(id: "global") { totalPublications dangerCount repoCount } }`,
    }),
  );
  if (!data?.registry) return null;
  return {
    totalPublications: Number(data.registry.totalPublications),
    dangerCount: Number(data.registry.dangerCount),
    repoCount: Number(data.registry.repoCount),
  };
}

interface RawRepo {
  name: string;
  commit: string;
  threatScore: number;
  verdict: string;
  reporter: string;
  scannedAt: string;
  publishCount: number;
}
interface RawStats {
  totalPublications: string;
  dangerCount: string;
  repoCount: string;
}

function normalize(r: RawRepo): RegistryEntry {
  const verdicts = ["Safe", "Caution", "Danger", "Unknown"] as const;
  return {
    name: r.name,
    commit: r.commit,
    threatScore: Number(r.threatScore),
    verdict: verdicts.includes(r.verdict as (typeof verdicts)[number])
      ? (r.verdict as RegistryEntry["verdict"])
      : "Unknown",
    reporter: r.reporter,
    scannedAt: Number(r.scannedAt),
    publishCount: Number(r.publishCount),
  };
}

/**
 * keccak256("owner/repo") — the subgraph's `Repo.id`, matching the contract's
 * `keccak256(bytes(repo))`.
 */
function repoIdHex(repoName: string): string {
  return keccak256(toBytes(repoName));
}

/**
 * Everything the community registry knows about a repo and its owner, shaped
 * for the analyzer to reason over. Fetched once, before analysis.
 */

export async function gatherPriorFlags(owner: string, name: string): Promise<PriorFlags | null> {
  if (!graphConfigured()) return null;
  const repoName = `${owner}/${name}`;
  const [repo, ownerRepos] = await Promise.all([lookupRepo(repoName), lookupOwner(owner, 10)]);

  // The owner's OTHER flagged repos — exclude this one.
  const others = ownerRepos.filter((r) => r.name !== repoName);

  return {
    repo: repo
      ? { verdict: repo.verdict, threatScore: repo.threatScore, publishCount: repo.publishCount }
      : null,
    owner: { flaggedRepoCount: others.length, names: others.slice(0, 8).map((r) => r.name) },
  };
}
