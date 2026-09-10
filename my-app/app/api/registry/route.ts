import { NextResponse } from "next/server";
import type { ThreatReport, Verdict } from "@/lib/analyzer/types";
import { graphConfigured, recentDangerous, registryStats, lookupRepo } from "@/lib/graph";
import { publishToRegistry, registryConfigured } from "@/lib/registry";

export const dynamic = "force-dynamic";

/**
 * GET  — read the community registry from The Graph (recent flags + totals),
 *        or look up one repo with `?repo=owner/name`.
 * POST — publish a scan verdict onchain.
 */
export async function GET(request: Request) {
  const repo = new URL(request.url).searchParams.get("repo");

  if (repo) {
    const entry = await lookupRepo(repo);
    return NextResponse.json({ entry, available: graphConfigured() });
  }

  const [recent, stats] = await Promise.all([recentDangerous(24), registryStats()]);
  return NextResponse.json({
    recent,
    stats,
    available: graphConfigured(),
    canPublish: registryConfigured(),
  });
}

interface PublishBody {
  owner: string;
  name: string;
  commit: string;
  threatScore: number;
  verdict: Verdict;
}

export async function POST(request: Request) {
  if (!registryConfigured()) {
    return NextResponse.json(
      { error: "The onchain registry is not configured on this server." },
      { status: 501 },
    );
  }

  let body: PublishBody;
  try {
    body = (await request.json()) as PublishBody;
  } catch {
    return NextResponse.json({ error: "Malformed request." }, { status: 400 });
  }

  if (!body.owner || !body.name || !body.commit || !body.verdict) {
    return NextResponse.json({ error: "Missing repository details." }, { status: 400 });
  }
  if (body.verdict === "safe") {
    // Publishing every clean repo would fill the registry with noise. The
    // registry is a warning list; only caution and danger are worth recording.
    return NextResponse.json(
      { error: "Only caution and danger verdicts are published to the registry." },
      { status: 400 },
    );
  }

  // A minimal report shape is enough for the writer.
  const report = {
    repo: { owner: body.owner, name: body.name, commit: body.commit },
    threatScore: Math.max(0, Math.min(100, Math.round(body.threatScore))),
    verdict: body.verdict,
  } as ThreatReport;

  try {
    const result = await publishToRegistry(report);
    return NextResponse.json(result);
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Publish failed." },
      { status: 502 },
    );
  }
}
