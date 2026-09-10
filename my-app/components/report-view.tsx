"use client";

import Link from "next/link";
import { useMemo } from "react";
import {
  AlertTriangle,
  Download,
  GitCommitHorizontal,
  Lock,
  RefreshCw,
  ShieldCheck,
  Star,
} from "lucide-react";
import type { Severity, ThreatReport } from "@/lib/analyzer/types";
import { countBySeverity } from "@/lib/analyzer/scorer";
import { ActionPlan } from "./action-plan";
import { CopyButton } from "./copy-button";
import { FindingCard } from "./finding-card";
import { RegistryPanel } from "./registry-panel";
import { ScoreRing } from "./score-ring";
import { SEVERITY_COLOR, VERDICT_COLOR, VERDICT_LABEL } from "./severity";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export function ReportView({ report }: { report: ThreatReport }) {
  const counts = useMemo(() => countBySeverity(report.findings), [report.findings]);
  const verdictColor = VERDICT_COLOR[report.verdict];
  const markdown = useMemo(() => toMarkdown(report), [report]);

  return (
    <div className="space-y-6">
      <section className="panel overflow-hidden">
        <div
          className="h-0.5 w-full"
          style={{ background: `linear-gradient(90deg, ${verdictColor}, transparent)` }}
        />
        <div className="flex flex-col gap-6 p-6 sm:flex-row sm:items-center">
          <ScoreRing score={report.threatScore} verdict={report.verdict} />

          <div className="min-w-0 flex-1">
            <p
              className="font-mono text-[0.7rem] uppercase tracking-[0.18em]"
              style={{ color: verdictColor }}
            >
              {VERDICT_LABEL[report.verdict]}
            </p>
            <h1 className="mt-1.5 truncate text-2xl font-semibold tracking-tight">
              {report.repo.owner}/{report.repo.name}
            </h1>

            <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1.5 font-mono text-xs text-[var(--color-faint)]">
              <span className="flex items-center gap-1.5">
                <GitCommitHorizontal size={13} />
                {report.repo.ref} @ {report.repo.commit.slice(0, 7)}
              </span>
              {report.repo.isPrivate ? (
                <span className="flex items-center gap-1.5">
                  <Lock size={12} />
                  private
                </span>
              ) : null}
              {typeof report.repo.stars === "number" ? (
                <span className="flex items-center gap-1.5">
                  <Star size={12} />
                  {report.repo.stars}
                </span>
              ) : null}
              <span>{(report.stats.durationMs / 1000).toFixed(1)}s</span>
            </div>

            <p className="mt-4 max-w-2xl text-sm leading-relaxed text-[var(--color-muted)]">
              {report.summary}
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 border-t border-[var(--color-border)] px-6 py-3">
          {SEVERITY_ORDER.filter((s) => counts[s] > 0).map((severity) => (
            <span
              key={severity}
              className="flex items-center gap-1.5 font-mono text-xs"
              style={{ color: SEVERITY_COLOR[severity] }}
            >
              <span
                className="size-1.5 rounded-full"
                style={{ background: SEVERITY_COLOR[severity] }}
              />
              {counts[severity]} {severity}
            </span>
          ))}
          {report.findings.length === 0 && !report.confidential ? (
            <span className="font-mono text-xs text-[var(--color-accent)]">
              no findings
            </span>
          ) : null}
          <RegistryPanel report={report} />

      {report.confidential ? (
            <span className="font-mono text-xs text-[var(--color-muted)]">
              {report.stats.filesFlagged} finding
              {report.stats.filesFlagged === 1 ? "" : "s"}, detail sealed in the enclave
            </span>
          ) : null}

          <div className="ml-auto flex items-center gap-2">
            <CopyButton text={markdown} label="Copy as Markdown" />
            <button
              type="button"
              className="btn btn-ghost"
              onClick={() => downloadJson(report)}
            >
              <Download size={14} />
              JSON
            </button>
            {!report.isSample ? (
              <Link
                href={`/scan?repo=${encodeURIComponent(report.repo.url)}`}
                className="btn btn-ghost"
              >
                <RefreshCw size={14} />
                Re-scan
              </Link>
            ) : null}
          </div>
        </div>
      </section>

      {report.confidential ? (
        <div
          className="panel flex gap-3 p-4"
          style={{ borderColor: "var(--color-accent-dim)" }}
        >
          <ShieldCheck size={16} className="mt-0.5 shrink-0 text-[var(--color-accent)]" />
          <div className="text-sm leading-relaxed text-[var(--color-muted)]">
            <p className="font-medium text-[var(--color-text)]">
              Analysed inside a Chainlink CRE enclave
            </p>
            <p className="mt-1">
              {report.stats.filesFlagged} finding
              {report.stats.filesFlagged === 1 ? " was" : "s were"} produced inside the
              Trusted Execution Environment and stayed there — the evidence quotes your
              repository&apos;s source, so only this verdict crossed the boundary. Neither
              this server nor the CRE node operator saw your code.
            </p>
          </div>
        </div>
      ) : null}

      {!report.confidential && report.stats.coverage < 0.6 && report.stats.filesConsidered > 0 ? (
        <div className="panel flex gap-3 p-4" style={{ borderColor: "var(--color-medium)" }}>
          <AlertTriangle size={16} className="mt-0.5 shrink-0 text-[var(--color-medium)]" />
          <div className="text-sm leading-relaxed text-[var(--color-muted)]">
            <p className="font-medium text-[var(--color-text)]">
              This scan read {report.stats.filesFetched} of{" "}
              {report.stats.filesConsidered.toLocaleString()} files (
              {(report.stats.coverage * 100).toFixed(
                report.stats.coverage < 0.01 ? 1 : 0,
              )}
              %)
            </p>
            <p className="mt-1">
              Repositories this size cannot be read in full within GitHub&apos;s
              rate limits, so RepoShield prioritised the files that execute on
              their own — manifests, install hooks, editor and CI config — plus
              anything anomalous. That covers the ways a repository runs code
              without being asked, which is the threat here.
              {report.verdict === "safe" ? (
                <>
                  {" "}
                  It does not cover the rest of the source. Read
                  &ldquo;nothing alarming found&rdquo; as &ldquo;nothing
                  alarming in what auto-executes&rdquo;, not as a clean bill of
                  health for {report.stats.filesConsidered.toLocaleString()}{" "}
                  files.
                </>
              ) : null}
            </p>
          </div>
        </div>
      ) : null}

      {report.degraded.length > 0 || report.stats.treeTruncated ? (
        <div className="panel flex gap-3 p-4" style={{ borderColor: "var(--color-border-strong)" }}>
          <AlertTriangle size={16} className="mt-0.5 shrink-0 text-[var(--color-medium)]" />
          <div className="space-y-1 text-sm text-[var(--color-muted)]">
            {report.stats.treeTruncated ? (
              <p>
                This repository is large enough that GitHub truncated its file
                listing. Some files were not visible to the scan.
              </p>
            ) : null}
            {report.degraded.map((note) => (
              <p key={note}>{note}</p>
            ))}
          </div>
        </div>
      ) : null}

      {report.confidential ? null : (
      <section className="panel p-5">
        <h2 className="text-sm font-semibold tracking-tight">What this project is</h2>
        <dl className="mt-3 grid gap-x-8 gap-y-3 sm:grid-cols-2 lg:grid-cols-4">
          <Fact label="Framework" value={report.profile.frameworks.join(", ")} />
          <Fact label="Languages" value={report.profile.languages.join(", ") || "—"} />
          <Fact
            label="Package manager"
            value={report.profile.packageManagers.join(", ") || "none detected"}
          />
          <Fact
            label="Lockfile"
            value={report.profile.hasLockfile ? "committed" : "missing"}
          />
        </dl>
        <p className="mt-4 border-t border-[var(--color-border)] pt-3 font-mono text-xs text-[var(--color-faint)]">
          {report.stats.filesInTree.toLocaleString()} files in tree ·{" "}
          {report.stats.filesFetched} of {report.stats.filesConsidered.toLocaleString()} read
          {report.stats.filesConsidered > 0
            ? ` (${(report.stats.coverage * 100).toFixed(report.stats.coverage < 0.01 ? 1 : 0)}%)`
            : ""}{" "}
          · {report.stats.filesFlagged} flagged by static rules ·{" "}
          {report.stats.filesAnalyzedByAI} reviewed by AI
        </p>
        {report.stats.filesVendored > 0 || report.stats.filesTest > 0 ? (
          <p className="mt-1.5 text-xs leading-relaxed text-[var(--color-muted)]">
            {report.stats.filesVendored > 0 ? (
              <>
                <strong className="font-medium text-[var(--color-text)]">
                  {report.stats.filesVendored.toLocaleString()}
                </strong>{" "}
                of those are third-party dependencies the author did not write
                {report.stats.filesTest > 0 ? ", and " : ". "}
              </>
            ) : null}
            {report.stats.filesTest > 0 ? (
              <>
                <strong className="font-medium text-[var(--color-text)]">
                  {report.stats.filesTest.toLocaleString()}
                </strong>{" "}
                are tests or fixtures.{" "}
              </>
            ) : null}
            Both are still scanned — a payload hidden in a dependency is still a
            payload — but findings there are weighted down, because libraries
            and test suites legitimately contain things that look alarming out
            of context.
          </p>
        ) : null}
      </section>
      )}

      <ActionPlan steps={report.actionPlan} />

      {report.findings.length > 0 ? (
        <section className="space-y-2.5">
          <h2 className="text-sm font-semibold tracking-tight">
            Findings ({report.findings.length})
          </h2>
          {report.findings.map((finding) => (
            <FindingCard key={finding.id} finding={finding} />
          ))}
        </section>
      ) : report.confidential ? null : (
        <section className="panel p-8 text-center">
          <p className="text-sm text-[var(--color-muted)]">
            No rule matched{" "}
            {report.stats.coverage < 0.6 && report.stats.filesConsidered > 0
              ? `anything in the ${report.stats.filesFetched} files we read`
              : "anything in this repository"}
            . That is a good sign — but it means nothing matched the patterns we
            know about, not that the code is proven safe. Read it before you run
            it.
          </p>
        </section>
      )}
    </div>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="font-mono text-[0.65rem] uppercase tracking-[0.16em] text-[var(--color-faint)]">
        {label}
      </dt>
      <dd className="mt-1 truncate text-sm">{value}</dd>
    </div>
  );
}

function downloadJson(report: ThreatReport) {
  const blob = new Blob([JSON.stringify(report, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `reposhield-${report.repo.owner}-${report.repo.name}-${report.repo.commit.slice(0, 7)}.json`;
  link.click();
  URL.revokeObjectURL(url);
}

/** Markdown export, so a developer can paste the report to a colleague. */
function toMarkdown(report: ThreatReport): string {
  const lines = [
    `# RepoShield — ${report.repo.owner}/${report.repo.name}`,
    "",
    `**${VERDICT_LABEL[report.verdict]}** — threat score ${report.threatScore}/100`,
    `Commit \`${report.repo.commit.slice(0, 7)}\` on \`${report.repo.ref}\` · scanned ${new Date(report.timestamp).toLocaleString()}`,
    "",
    report.summary,
    "",
  ];

  if (report.findings.length > 0) {
    lines.push(`## Findings (${report.findings.length})`, "");
    for (const finding of report.findings) {
      lines.push(
        `### [${finding.severity.toUpperCase()}] ${finding.title}`,
        `\`${finding.file}${finding.line ? `:${finding.line}` : ""}\` · ${finding.ruleId} · ${finding.phase === "ai" ? "AI" : "static"}`,
        "",
        finding.description,
        "",
        "```",
        finding.evidence,
        "```",
        "",
        `**What to do:** ${finding.recommendation}`,
        "",
      );
    }
  }

  if (report.actionPlan.length > 0) {
    lines.push("## What to do now", "");
    report.actionPlan.forEach((step, i) => {
      lines.push(`${i + 1}. **${step.title}** — ${step.detail}`);
      if (step.command) lines.push("", "```bash", step.command, "```", "");
    });
  }

  return lines.join("\n");
}
