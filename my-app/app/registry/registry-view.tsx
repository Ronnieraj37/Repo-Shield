"use client";

import Link from "next/link";
import { Database, ExternalLink, ShieldAlert } from "lucide-react";
import type { RegistryEntry, RegistryStats } from "@/lib/graph";
import { VERDICT_COLOR } from "@/components/severity";

/**
 * The public registry, read live from The Graph.
 *
 * Every row here was published onchain by someone else. That is the whole
 * point: a scan tells you what one machine found now; this tells you what the
 * community has found, permanently, and survives the tool that produced it.
 */
export function RegistryView({
  available,
  recent,
  stats,
}: {
  available: boolean;
  recent: RegistryEntry[];
  stats: RegistryStats | null;
}) {
  return (
    <div className="space-y-6">
      <header>
        <div className="inline-flex items-center gap-2 rounded-full border border-[var(--color-border-strong)] px-3 py-1 font-mono text-[0.68rem] uppercase tracking-[0.14em] text-[var(--color-muted)]">
          <Database size={12} className="text-[var(--color-accent)]" />
          Onchain · indexed by The Graph
        </div>
        <h1 className="mt-4 text-2xl font-semibold tracking-tight">
          Community registry
        </h1>
        <p className="mt-2 max-w-2xl text-sm leading-relaxed text-[var(--color-muted)]">
          Repositories flagged by RepoShield users, written to a contract on
          Sepolia and indexed by The Graph. A scan tells you what your machine
          found just now; this tells you what everyone else has found — and it
          outlives any single scan.
        </p>
      </header>

      {!available ? (
        <div className="panel p-8 text-center">
          <p className="text-sm text-[var(--color-muted)]">
            The registry is not configured on this deployment.
          </p>
        </div>
      ) : (
        <>
          {stats ? (
            <div className="grid grid-cols-3 gap-3">
              <Stat label="Repos flagged" value={stats.repoCount} />
              <Stat label="Marked danger" value={stats.dangerCount} accent="var(--color-critical)" />
              <Stat label="Total reports" value={stats.totalPublications} />
            </div>
          ) : null}

          <section className="space-y-2">
            <h2 className="text-sm font-semibold tracking-tight">Recently flagged</h2>
            {recent.length === 0 ? (
              <div className="panel p-8 text-center">
                <p className="text-sm text-[var(--color-muted)]">
                  Nothing flagged yet. Scan a repository and publish the verdict
                  to be the first.
                </p>
                <Link href="/scan" className="btn btn-primary mt-4">
                  Scan a repository
                </Link>
              </div>
            ) : (
              <ul className="space-y-2">
                {recent.map((entry) => (
                  <li key={`${entry.name}-${entry.commit}`} className="panel flex items-center gap-4 p-4">
                    <span
                      className="font-mono text-lg font-semibold tabular-nums"
                      style={{ color: VERDICT_COLOR[verdictKey(entry.verdict)] }}
                    >
                      {entry.threatScore}
                    </span>
                    <div className="min-w-0 flex-1">
                      <a
                        href={`https://github.com/${entry.name}`}
                        target="_blank"
                        rel="noreferrer"
                        className="flex items-center gap-1.5 truncate text-sm font-medium hover:underline"
                      >
                        {entry.name}
                        <ExternalLink size={11} className="shrink-0 text-[var(--color-faint)]" />
                      </a>
                      <p className="mt-0.5 font-mono text-xs text-[var(--color-faint)]">
                        {entry.commit.slice(0, 9)} · {relativeTime(entry.scannedAt)}
                        {entry.publishCount > 1 ? ` · flagged ${entry.publishCount}×` : ""}
                      </p>
                    </div>
                    <span
                      className="flex items-center gap-1.5 font-mono text-[0.7rem] uppercase tracking-wide"
                      style={{ color: VERDICT_COLOR[verdictKey(entry.verdict)] }}
                    >
                      {entry.verdict === "Danger" ? <ShieldAlert size={12} /> : null}
                      {entry.verdict}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </>
      )}
    </div>
  );
}

function Stat({ label, value, accent }: { label: string; value: number; accent?: string }) {
  return (
    <div className="panel p-4">
      <p className="font-mono text-2xl font-semibold tabular-nums" style={accent ? { color: accent } : undefined}>
        {value.toLocaleString()}
      </p>
      <p className="mt-1 font-mono text-[0.65rem] uppercase tracking-[0.14em] text-[var(--color-faint)]">
        {label}
      </p>
    </div>
  );
}

function verdictKey(v: RegistryEntry["verdict"]): Verdict {
  return v === "Danger" ? "danger" : v === "Caution" ? "caution" : "safe";
}

type Verdict = "safe" | "caution" | "danger";

function relativeTime(unixSeconds: number): string {
  const seconds = Date.now() / 1000 - unixSeconds;
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}
