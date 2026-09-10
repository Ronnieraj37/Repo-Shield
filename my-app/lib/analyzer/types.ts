/**
 * Shared types for the RepoShield analysis pipeline.
 *
 * Nothing in `lib/analyzer` performs I/O. The caller (a Next route handler, or
 * the Chainlink CRE `handlerInTee`) is responsible for fetching the repo; the
 * analyzer is a pure function over the result. That is what lets the exact same
 * code run on a laptop and inside a TEE.
 */

export type FrameworkType =
  | "foundry"
  | "hardhat"
  | "truffle"
  | "anchor"
  | "cargo"
  | "go"
  | "nodejs"
  | "python"
  | "deno"
  | "bun"
  | "unknown";

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Verdict = "safe" | "caution" | "danger";
export type Phase = "static" | "ai";

export const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

/** One entry from the GitHub git-tree API (or a bundled sample). */
export interface FileEntry {
  path: string;
  type: "blob" | "tree";
  size?: number;
}

export interface ProjectProfile {
  frameworks: FrameworkType[];
  languages: string[];
  packageManagers: string[];
  /** Files the detector wants fetched because they are risky by nature. */
  filesOfInterest: string[];
  hasLockfile: boolean;
  fileCount: number;
}

export interface Finding {
  /** Stable within a report: `${ruleId}:${file}:${line ?? 0}`. */
  id: string;
  ruleId: string;
  severity: Severity;
  phase: Phase;
  /** e.g. "lifecycle-script", "obfuscation", "credential-access". */
  category: string;
  title: string;
  description: string;
  file: string;
  line?: number;
  /** The offending snippet, already truncated for display. */
  evidence: string;
  recommendation: string;
  /** Populated in phase 2 when Gemini reviewed this file. */
  aiExplanation?: string;
  confirmedByAI?: boolean;
}

export interface ActionStep {
  title: string;
  detail: string;
  /** Copy-pasteable shell, when there is one. */
  command?: string;
  /** Ordering hint: lower runs first. */
  priority: number;
}

export interface RepoMeta {
  owner: string;
  name: string;
  url: string;
  ref: string;
  commit: string;
  isPrivate: boolean;
  stars?: number;
  pushedAt?: string;
  defaultBranch?: string;
  /** Repository size in KB, as GitHub reports it. */
  sizeKb?: number;
}

export interface ReportStats {
  filesInTree: number;
  /** Blobs that were candidates, i.e. excluding vendored/build directories. */
  filesConsidered: number;
  filesFetched: number;
  /** filesFetched / filesConsidered. Surfaced, never hidden. */
  coverage: number;
  filesFlagged: number;
  filesAnalyzedByAI: number;
  /** Third-party code — dependencies the repo author did not write. */
  filesVendored: number;
  /** Tests, fixtures and mocks. */
  filesTest: number;
  durationMs: number;
  treeTruncated: boolean;
}

export interface ThreatReport {
  /** sha256(`${owner}/${name}@${commit}`) truncated — addressable and dedupable. */
  id: string;
  repo: RepoMeta;
  timestamp: string;
  profile: ProjectProfile;
  threatScore: number;
  verdict: Verdict;
  findings: Finding[];
  summary: string;
  actionPlan: ActionStep[];
  stats: ReportStats;
  /** Non-fatal degradations, e.g. "AI phase skipped: no API key configured". */
  degraded: string[];
  /** True when the report came from a bundled fixture rather than GitHub. */
  isSample?: boolean;
  /**
   * True when the analysis ran inside a CRE enclave. Such a report carries a
   * verdict but no findings — the evidence never left the TEE.
   */
  confidential?: boolean;
}

/** Progress events streamed to the client over SSE during a scan. */
export type ScanEvent =
  | { type: "stage"; stage: ScanStage; message: string; detail?: string }
  | { type: "finding"; finding: Finding }
  | { type: "done"; report: ThreatReport }
  | { type: "error"; code: string; message: string };

export type ScanStage =
  | "resolving"
  | "tree"
  | "fetching"
  | "static"
  | "ai"
  | "scoring"
  | "done";

/** Everything the analyzer needs, and nothing it doesn't. */
export interface AnalyzeInput {
  repo: RepoMeta;
  tree: FileEntry[];
  /** path -> decoded UTF-8 contents. Binary files are omitted. */
  contents: Map<string, string>;
  treeTruncated?: boolean;
  isSample?: boolean;
  /** Candidate blobs, when the caller filtered before fetching. */
  filesConsidered?: number;
}

export interface AnalyzeOptions {
  /** Transport for the AI phase. Without it, phase 2 is skipped. */
  http?: import("./http").HttpClient;
  geminiApiKey?: string;
  /** Override the Gemini API origin (used by CRE simulation against a mock). */
  geminiEndpointBase?: string;
  /** Skip phase 2 entirely (offline dev, tests). */
  skipAI?: boolean;
  onEvent?: (event: ScanEvent) => void;
}
