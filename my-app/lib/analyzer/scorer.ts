import type { Finding, Severity, Verdict } from "./types";

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
  info: 0,
};

/** A finding Gemini independently confirmed counts for more than a regex hit. */
const AI_CONFIRMED_MULTIPLIER = 1.5;

/**
 * Diminishing returns per category: twelve unpinned actions is one problem,
 * not twelve. Without this a noisy-but-harmless repo outscores a quiet
 * backdoor, which is exactly the wrong ranking.
 */
const REPEAT_DECAY = 0.5;

export function calculateScore(findings: Finding[]): {
  threatScore: number;
  verdict: Verdict;
} {
  const countByCategory = new Map<string, number>();
  let score = 0;

  const ordered = [...findings].sort(
    (a, b) => SEVERITY_WEIGHT[b.severity] - SEVERITY_WEIGHT[a.severity],
  );

  for (const finding of ordered) {
    const seen = countByCategory.get(finding.category) ?? 0;
    countByCategory.set(finding.category, seen + 1);

    const base = SEVERITY_WEIGHT[finding.severity];
    const multiplier = finding.confirmedByAI ? AI_CONFIRMED_MULTIPLIER : 1;
    score += base * multiplier * Math.pow(REPEAT_DECAY, seen);
  }

  let threatScore = Math.min(100, Math.round(score));

  // A single confirmed reverse shell is a danger verdict no matter what the
  // arithmetic says. Severity floors override the additive model.
  const hasCritical = findings.some((f) => f.severity === "critical");
  const hasHigh = findings.some((f) => f.severity === "high");
  if (hasCritical) threatScore = Math.max(threatScore, 61);
  else if (hasHigh) threatScore = Math.max(threatScore, 31);

  return { threatScore, verdict: toVerdict(threatScore) };
}

export function toVerdict(score: number): Verdict {
  if (score <= 30) return "safe";
  if (score <= 60) return "caution";
  return "danger";
}

export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const finding of findings) counts[finding.severity]++;
  return counts;
}

/**
 * The fallback summary, used when the AI phase is skipped or fails. Reads like
 * a person wrote it rather than like a template, because for a developer
 * staring at a red score this sentence is the whole report.
 */
export function buildStaticSummary(
  findings: Finding[],
  verdict: Verdict,
  repoName: string,
): string {
  const counts = countBySeverity(findings);
  if (findings.length === 0) {
    return `Static analysis found nothing dangerous in ${repoName}. No install-time scripts, no auto-executing editor config, no references to credential paths. That is a good sign, but it is not a guarantee — it means nothing matched the patterns we know about.`;
  }

  const topCategories = [...new Set(findings.map((f) => f.category))].slice(0, 3);
  const parts: string[] = [];

  if (verdict === "danger") {
    parts.push(
      `${repoName} contains code that runs without you asking it to, and it matches patterns used in real attacks on developers.`,
    );
  } else if (verdict === "caution") {
    parts.push(
      `${repoName} has a few things worth reading before you run it. None are conclusive on their own.`,
    );
  } else {
    parts.push(
      `${repoName} looks broadly ordinary, with minor issues that are common in real projects.`,
    );
  }

  const severityBits = (["critical", "high", "medium", "low"] as Severity[])
    .filter((s) => counts[s] > 0)
    .map((s) => `${counts[s]} ${s}`);
  parts.push(
    `We found ${findings.length} issue${findings.length === 1 ? "" : "s"} (${severityBits.join(", ")}), mainly around ${topCategories.join(", ")}.`,
  );

  const worst = findings.find((f) => f.severity === "critical") ?? findings[0];
  parts.push(`The most serious is in \`${worst.file}\`: ${worst.title.toLowerCase()}.`);

  return parts.join(" ");
}
