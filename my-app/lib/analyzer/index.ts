import { detectProject } from "./detector";
import { analyzeWithGemini, type FlaggedFile } from "./gemini";
import { sha256Hex } from "./portable";
import { buildActionPlan } from "./remediation";
import { applyRules, buildRuleContext } from "./rules";
import { buildStaticSummary, calculateScore } from "./scorer";
import type {
  AnalyzeInput,
  AnalyzeOptions,
  Finding,
  ThreatReport,
} from "./types";

export * from "./types";
export type { HttpClient, HttpRequest, HttpResponse } from "./http";
export { detectProject, selectFilesToFetch } from "./detector";
export { calculateScore, countBySeverity, toVerdict } from "./scorer";

/**
 * The whole pipeline, as one pure-ish function.
 *
 * "Pure-ish": the only I/O is the optional Gemini call in phase 2. Everything
 * else operates on the file contents handed in by the caller. That is what
 * lets this exact function run in a Next route handler during development and
 * inside a Chainlink CRE `handlerInTee` in production, with no branching.
 */
export async function analyzeRepo(
  input: AnalyzeInput,
  options: AnalyzeOptions = {},
): Promise<ThreatReport> {
  const startedAt = Date.now();
  const emit = options.onEvent ?? (() => {});
  const degraded: string[] = [];

  const repoName = `${input.repo.owner}/${input.repo.name}`;
  // How much of the repository we actually read. A "safe" verdict over a
  // fraction of a monorepo is not a verdict, and the report has to say so.
  const considered =
    input.filesConsidered ?? input.tree.filter((e) => e.type === "blob").length;

  // --- Detection -----------------------------------------------------------
  emit({ type: "stage", stage: "static", message: "Detecting project type" });
  const profile = detectProject(input.tree);

  // --- Phase 1: static heuristics -----------------------------------------
  emit({
    type: "stage",
    stage: "static",
    message: "Running static analysis",
    detail: `${input.contents.size} files`,
  });
  const context = buildRuleContext(input.tree, input.contents);

  // How the repository breaks down. A scan that read 720 files but where 660
  // are vendored dependencies is a very different thing from one where the
  // author wrote all 720, and the report should not make the reader guess.
  let filesVendored = 0;
  let filesTest = 0;
  for (const path of input.contents.keys()) {
    const cls = context.classes.get(path);
    if (!cls) continue;
    if (cls.vendored) filesVendored++;
    else if (cls.test) filesTest++;
  }
  const staticFindings = applyRules(context);
  for (const finding of staticFindings) emit({ type: "finding", finding });

  // --- Phase 2: AI on flagged files only ----------------------------------
  const flagged = collectFlaggedFiles(staticFindings, input.contents);
  let aiFindings: Finding[] = [];
  let aiSummary: string | null = null;
  let filesAnalyzedByAI = 0;

  if (options.skipAI) {
    if (flagged.length > 0) {
      degraded.push("AI analysis was skipped for this scan.");
    }
  } else if (!options.http) {
    if (flagged.length > 0) {
      degraded.push(
        "No HTTP client was supplied to the analyzer, so the AI phase could not run.",
      );
    }
  } else if (!options.geminiApiKey) {
    if (flagged.length > 0) {
      degraded.push(
        "No Gemini API key is configured, so flagged files were not reviewed by AI. Static findings only.",
      );
    }
  } else if (flagged.length > 0) {
    emit({
      type: "stage",
      stage: "ai",
      message: "AI reviewing flagged files",
      detail: `${flagged.length} file${flagged.length === 1 ? "" : "s"}`,
    });
    const result = await analyzeWithGemini(
      flagged,
      options.geminiApiKey,
      repoName,
      options.http,
      options.geminiEndpointBase,
    );
    aiFindings = dedupeAgainstStatic(result.findings, staticFindings);
    aiSummary = result.summary;
    filesAnalyzedByAI = result.filesAnalyzed;
    if (result.error) degraded.push(result.error);
    for (const finding of aiFindings) emit({ type: "finding", finding });

    // Phase 1 found the file; Phase 2 confirmed it's actually bad. Mark the
    // static findings on those files so the scorer weights them higher.
    markConfirmed(staticFindings, aiFindings);
  }

  // --- Scoring -------------------------------------------------------------
  emit({ type: "stage", stage: "scoring", message: "Scoring" });
  const findings = sortFindings([...staticFindings, ...aiFindings]);
  const { threatScore, verdict } = calculateScore(findings);

  const summary =
    aiSummary?.trim() || buildStaticSummary(findings, verdict, repoName);

  return {
    id: reportId(repoName, input.repo.commit),
    repo: input.repo,
    timestamp: new Date().toISOString(),
    profile,
    threatScore,
    verdict,
    findings,
    summary,
    actionPlan: buildActionPlan(findings, profile, verdict, input.repo.url),
    stats: {
      filesInTree: input.tree.filter((e) => e.type === "blob").length,
      filesConsidered: considered,
      filesFetched: input.contents.size,
      coverage: considered === 0 ? 1 : Math.min(1, input.contents.size / considered),
      filesFlagged: flagged.length,
      filesAnalyzedByAI,
      filesVendored,
      filesTest,
      durationMs: Date.now() - startedAt,
      treeTruncated: input.treeTruncated ?? false,
    },
    degraded,
    isSample: input.isSample,
  };
}

/**
 * Which files earned a trip to the model, and why.
 *
 * The reasons matter: handing Gemini "this file tripped R16 (credential paths)
 * and R29 (env exfiltration)" gets a far more focused answer than handing it
 * the file alone.
 */
function collectFlaggedFiles(
  findings: Finding[],
  contents: Map<string, string>,
): FlaggedFile[] {
  const reasonsByFile = new Map<string, Set<string>>();
  for (const finding of findings) {
    if (finding.severity === "low" || finding.severity === "info") continue;
    if (!contents.has(finding.file)) continue;
    const set = reasonsByFile.get(finding.file) ?? new Set<string>();
    set.add(`${finding.ruleId} — ${finding.title}`);
    reasonsByFile.set(finding.file, set);
  }

  return [...reasonsByFile.entries()].map(([path, reasons]) => ({
    path,
    content: contents.get(path)!,
    reasons: [...reasons],
  }));
}

/**
 * Drop AI findings that restate a static finding on the same file.
 *
 * Without this the report double-counts: the regex says "postinstall pipes
 * curl to bash", the model says the same thing in nicer prose, and the score
 * doubles for one problem. The static finding survives and gets the AI's
 * explanation attached to it instead.
 */
function dedupeAgainstStatic(
  aiFindings: Finding[],
  staticFindings: Finding[],
): Finding[] {
  return aiFindings.filter((ai) => {
    const overlapping = staticFindings.filter((s) => s.file === ai.file);
    if (overlapping.length === 0) return true;
    const aiWords = tokenize(ai.title);
    return !overlapping.some((s) => {
      const shared = tokenize(s.title).filter((w) => aiWords.includes(w));
      return shared.length >= 2;
    });
  });
}

function markConfirmed(staticFindings: Finding[], aiFindings: Finding[]): void {
  const aiFiles = new Set(aiFindings.map((f) => f.file));
  for (const finding of staticFindings) {
    if (!aiFiles.has(finding.file)) continue;
    finding.confirmedByAI = true;
    finding.aiExplanation = aiFindings.find(
      (ai) => ai.file === finding.file,
    )?.aiExplanation;
  }
}

const STOPWORDS = new Set([
  "the", "a", "an", "in", "of", "to", "and", "or", "for", "with", "code",
  "file", "script", "that", "this", "from", "is", "at", "on", "into",
]);

function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((w) => w.length > 2 && !STOPWORDS.has(w));
}

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const bySeverity = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
    if (bySeverity !== 0) return bySeverity;
    // AI-confirmed first within a severity — those are the ones with an
    // explanation attached, and they're what the developer should read first.
    if (a.confirmedByAI !== b.confirmedByAI) return a.confirmedByAI ? -1 : 1;
    return a.file.localeCompare(b.file);
  });
}

/**
 * Deterministic report id from repo + commit, so re-scanning the same commit
 * addresses the same report and a force-push produces a new one.
 *
 * Hashed with the portable SHA-256 rather than Web Crypto: `crypto` is one of
 * the modules the CRE WASM runtime types as `never`.
 */
function reportId(repoName: string, commit: string): string {
  return sha256Hex(`${repoName}@${commit}`).slice(0, 16);
}
