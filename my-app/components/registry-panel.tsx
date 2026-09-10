"use client";

import { useEffect, useState } from "react";
import { Check, Database, ExternalLink, Loader2, ShieldAlert, Upload } from "lucide-react";
import type { ThreatReport } from "@/lib/analyzer/types";
import type { RegistryEntry } from "@/lib/graph";

/**
 * The onchain-registry surface on a report: what the community already knows
 * about this repo (read from The Graph), and the option to publish this
 * verdict for the next person.
 */
export function RegistryPanel({ report }: { report: ThreatReport }) {
  const repoName = `${report.repo.owner}/${report.repo.name}`;

  const [state, setState] = useState<{
    available: boolean;
    canPublish: boolean;
    prior: RegistryEntry | null;
  } | null>(null);
  const [publishing, setPublishing] = useState(false);
  const [published, setPublished] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (report.isSample) return;
    let cancelled = false;
    (async () => {
      const [rootRes, repoRes] = await Promise.all([
        fetch("/api/registry").then((r) => r.json()).catch(() => null),
        fetch(`/api/registry?repo=${encodeURIComponent(repoName)}`)
          .then((r) => r.json())
          .catch(() => null),
      ]);
      if (cancelled) return;
      setState({
        available: Boolean(rootRes?.available),
        canPublish: Boolean(rootRes?.canPublish),
        prior: (repoRes?.entry as RegistryEntry | null) ?? null,
      });
    })();
    return () => {
      cancelled = true;
    };
  }, [repoName, report.isSample]);

  // Nothing to show for samples, or when the registry isn't configured.
  if (report.isSample || !state?.available) return null;

  const publishable = report.verdict !== "safe" && state.canPublish;

  return (
    <div className="panel p-4" style={{ borderColor: "var(--color-border-strong)" }}>
      <div className="flex items-start gap-3">
        <Database size={16} className="mt-0.5 shrink-0 text-[var(--color-accent)]" />
        <div className="min-w-0 flex-1">
          {state.prior ? (
            <p className="text-sm leading-relaxed">
              <span className="font-medium">
                This repository is already in the community registry.
              </span>{" "}
              <span className="text-[var(--color-muted)]">
                Flagged{" "}
                <strong style={{ color: "var(--color-text)" }}>
                  {state.prior.publishCount}×
                </strong>{" "}
                — last verdict{" "}
                <strong style={{ color: "var(--color-text)" }}>
                  {state.prior.verdict}
                </strong>{" "}
                ({state.prior.threatScore}/100). Indexed by The Graph.
              </span>
            </p>
          ) : (
            <p className="text-sm leading-relaxed text-[var(--color-muted)]">
              Not yet in the community registry.{" "}
              {publishable
                ? "Publish this verdict onchain so the next person sent this repo can find it."
                : report.verdict === "safe"
                  ? "Only caution and danger verdicts are worth recording."
                  : "Publishing is not enabled on this deployment."}
            </p>
          )}

          {published ? (
            <a
              href={published}
              target="_blank"
              rel="noreferrer"
              className="mt-3 inline-flex items-center gap-1.5 text-sm text-[var(--color-accent)] hover:underline"
            >
              <Check size={14} /> Published onchain — view transaction
              <ExternalLink size={12} />
            </a>
          ) : publishable ? (
            <button
              type="button"
              className="btn btn-ghost mt-3"
              disabled={publishing}
              onClick={async () => {
                setPublishing(true);
                setError(null);
                try {
                  const res = await fetch("/api/registry", {
                    method: "POST",
                    headers: { "content-type": "application/json" },
                    body: JSON.stringify({
                      owner: report.repo.owner,
                      name: report.repo.name,
                      commit: report.repo.commit,
                      threatScore: report.threatScore,
                      verdict: report.verdict,
                    }),
                  });
                  const data = await res.json();
                  if (!res.ok) throw new Error(data.error ?? "Publish failed.");
                  setPublished(data.explorerUrl);
                } catch (e) {
                  setError(e instanceof Error ? e.message : "Publish failed.");
                } finally {
                  setPublishing(false);
                }
              }}
            >
              {publishing ? (
                <Loader2 size={14} className="animate-spin" />
              ) : report.verdict === "danger" ? (
                <ShieldAlert size={14} />
              ) : (
                <Upload size={14} />
              )}
              {publishing ? "Publishing…" : "Publish verdict onchain"}
            </button>
          ) : null}

          {error ? (
            <p className="mt-2 text-xs text-[var(--color-critical)]">{error}</p>
          ) : null}
        </div>
      </div>
    </div>
  );
}
