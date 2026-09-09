"use client";

import { useState } from "react";
import { ChevronRight, Sparkles } from "lucide-react";
import type { Finding } from "@/lib/analyzer/types";
import { PhaseBadge, SEVERITY_COLOR, SeverityBadge } from "./severity";

export function FindingCard({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(finding.severity === "critical");
  const color = SEVERITY_COLOR[finding.severity];

  return (
    <div
      className="panel overflow-hidden transition-colors"
      style={{ borderLeft: `2px solid ${color}` }}
    >
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="flex w-full items-start gap-3 p-4 text-left transition-colors hover:bg-[var(--color-surface-2)]"
      >
        <ChevronRight
          size={16}
          className="mt-0.5 shrink-0 text-[var(--color-faint)] transition-transform"
          style={{ transform: open ? "rotate(90deg)" : "none" }}
        />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            <PhaseBadge phase={finding.phase} />
            {finding.confirmedByAI && finding.phase === "static" ? (
              <span
                className="flex items-center gap-1 font-mono text-[0.68rem]"
                style={{ color: "#c4a3ff" }}
                title="Static analysis flagged this file and AI review confirmed it"
              >
                <Sparkles size={10} />
                AI-confirmed
              </span>
            ) : null}
            <span className="ml-auto font-mono text-[0.7rem] text-[var(--color-faint)]">
              {finding.ruleId}
            </span>
          </div>
          <h3 className="mt-1.5 font-medium leading-snug">{finding.title}</h3>
          <p className="mt-1 truncate font-mono text-xs text-[var(--color-muted)]">
            {finding.file}
            {finding.line ? `:${finding.line}` : ""}
          </p>
        </div>
      </button>

      {open ? (
        <div className="animate-fade-up space-y-4 border-t border-[var(--color-border)] px-4 py-4">
          <p className="text-sm leading-relaxed text-[var(--color-muted)]">
            {finding.description}
          </p>

          {finding.evidence ? (
            <div>
              <Label>Evidence</Label>
              <pre className="code-block mt-1.5 whitespace-pre-wrap break-all">
                {finding.evidence}
              </pre>
            </div>
          ) : null}

          {finding.aiExplanation && finding.aiExplanation !== finding.description ? (
            <div>
              <Label icon>What this actually does</Label>
              <p className="mt-1.5 rounded-lg border border-[rgba(196,163,255,0.18)] bg-[rgba(196,163,255,0.05)] px-3 py-2.5 text-sm leading-relaxed text-[var(--color-muted)]">
                {finding.aiExplanation}
              </p>
            </div>
          ) : null}

          <div>
            <Label>What to do</Label>
            <p className="mt-1.5 text-sm leading-relaxed" style={{ color }}>
              {finding.recommendation}
            </p>
          </div>
        </div>
      ) : null}
    </div>
  );
}

function Label({ children, icon }: { children: React.ReactNode; icon?: boolean }) {
  return (
    <span className="flex items-center gap-1.5 font-mono text-[0.65rem] uppercase tracking-[0.16em] text-[var(--color-faint)]">
      {icon ? <Sparkles size={10} style={{ color: "#c4a3ff" }} /> : null}
      {children}
    </span>
  );
}
