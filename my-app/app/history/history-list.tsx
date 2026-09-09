"use client";

import Link from "next/link";
import { Trash2 } from "lucide-react";
import { VERDICT_COLOR, VERDICT_LABEL } from "@/components/severity";
import { clearReports, deleteReport, useReports } from "@/lib/store";

export function HistoryList() {
  const reports = useReports();

  return (
    <div>
      <div className="flex items-baseline justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Scan history</h1>
          <p className="mt-1.5 text-sm text-[var(--color-muted)]">
            Stored in this browser only. Nothing here was ever sent to a server.
          </p>
        </div>
        {reports.length > 0 ? (
          <button type="button" className="btn btn-ghost" onClick={clearReports}>
            Clear all
          </button>
        ) : null}
      </div>

      {reports.length === 0 ? (
        <div className="panel mt-6 p-8 text-center">
          <p className="text-sm text-[var(--color-muted)]">No scans yet.</p>
          <Link href="/scan" className="btn btn-primary mt-4">
            Scan a repository
          </Link>
        </div>
      ) : (
        <ul className="mt-6 space-y-2">
          {reports.map(({ report, savedAt }) => (
            <li key={report.id} className="panel flex items-center gap-4 p-4">
              <span
                className="font-mono text-lg font-semibold tabular-nums"
                style={{ color: VERDICT_COLOR[report.verdict] }}
              >
                {report.threatScore}
              </span>
              <Link href={`/report/${report.id}`} className="min-w-0 flex-1">
                <p className="truncate text-sm font-medium">
                  {report.repo.owner}/{report.repo.name}
                </p>
                <p className="mt-0.5 font-mono text-xs text-[var(--color-faint)]">
                  {report.repo.commit.slice(0, 7)} · {report.findings.length} findings ·{" "}
                  {new Date(savedAt).toLocaleDateString()}
                </p>
              </Link>
              <span
                className="hidden shrink-0 font-mono text-[0.7rem] sm:block"
                style={{ color: VERDICT_COLOR[report.verdict] }}
              >
                {VERDICT_LABEL[report.verdict]}
              </span>
              <button
                type="button"
                aria-label={`Delete report for ${report.repo.owner}/${report.repo.name}`}
                className="shrink-0 rounded p-1.5 text-[var(--color-faint)] transition-colors hover:text-[var(--color-critical)]"
                onClick={() => deleteReport(report.id)}
              >
                <Trash2 size={14} />
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
