import type { Severity, Verdict } from "@/lib/analyzer/types";

export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "var(--color-critical)",
  high: "var(--color-high)",
  medium: "var(--color-medium)",
  low: "var(--color-low)",
  info: "var(--color-info)",
};

export const VERDICT_COLOR: Record<Verdict, string> = {
  safe: "var(--color-accent)",
  caution: "var(--color-medium)",
  danger: "var(--color-critical)",
};

export const VERDICT_LABEL: Record<Verdict, string> = {
  safe: "Nothing alarming found",
  caution: "Read before you run it",
  danger: "Do not run this",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  const color = SEVERITY_COLOR[severity];
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded px-1.5 py-0.5 font-mono text-[0.68rem] font-medium uppercase tracking-wider"
      style={{ color, background: `color-mix(in srgb, ${color} 12%, transparent)` }}
    >
      <span className="size-1.5 rounded-full" style={{ background: color }} />
      {severity}
    </span>
  );
}

export function PhaseBadge({ phase }: { phase: "static" | "ai" }) {
  return (
    <span
      className="rounded px-1.5 py-0.5 font-mono text-[0.68rem] tracking-wide"
      style={{
        color: phase === "ai" ? "#c4a3ff" : "var(--color-faint)",
        background:
          phase === "ai" ? "rgba(196,163,255,0.1)" : "var(--color-surface-2)",
      }}
      title={
        phase === "ai"
          ? "Found by AI analysis of a file that static rules flagged"
          : "Found by a static pattern rule, with no AI involved"
      }
    >
      {phase === "ai" ? "AI" : "STATIC"}
    </span>
  );
}
