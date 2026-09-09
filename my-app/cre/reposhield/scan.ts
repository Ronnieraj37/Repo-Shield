import { analyzeRepo } from "../../lib/analyzer";
import type { HttpClient } from "../../lib/analyzer/http";
import type { Finding } from "../../lib/analyzer/types";
import {
  fetchFiles,
  fetchRepoMeta,
  fetchTree,
  parseRepoInput,
} from "../../lib/github";

/**
 * The confidential body of the workflow, as a plain function.
 *
 * Everything the enclave actually does lives here, behind two injected
 * dependencies rather than the CRE runtime itself. That is deliberate:
 *
 *   - `workflow.ts` wires in the real `TeeRuntime` and confidential-http
 *   - `test/run-confidential-scan.mts` wires in a fake secret store and a
 *     recorded transport, and runs the identical code on a laptop
 *
 * Without this split the only way to execute any of this is to deploy it,
 * which means the logic would be unverified until the moment it matters.
 */

export interface ScanRequest {
  /** `owner/repo`, a GitHub URL, or an SSH clone string. */
  repo: string;
  /** Branch, tag or SHA. Defaults to the repository's default branch. */
  ref?: string;
}

/** Everything that crosses back out of the enclave. Deliberately small. */
export interface ScanVerdict {
  repo: string;
  commit: string;
  threatScore: number;
  verdict: string;
  findingCount: number;
  criticalCount: number;
  scannedAt: string;
}

export interface ConfidentialScanDeps {
  /** Reads a secret. Backed by the Vault DON inside the enclave. */
  getSecret: (id: string) => string;
  /** Outbound transport. Backed by confidential-http inside the enclave. */
  http: HttpClient;
  log: (message: string) => void;
  /**
   * API origins. Configurable because the CRE simulator has no route to the
   * public internet — `cre workflow simulate` points these at a local mock,
   * exactly as the official audit-firewall template does.
   */
  githubApiBase?: string;
  geminiEndpointBase?: string;
  /** Vault ids for the two secrets, when they differ from the defaults. */
  githubTokenId?: string;
  geminiKeyId?: string;
}

export async function runConfidentialScan(
  request: ScanRequest,
  deps: ConfidentialScanDeps,
): Promise<ScanVerdict> {
  if (!request?.repo) {
    throw new Error("Request body must include a `repo`.");
  }

  // Secrets are decrypted here, inside the enclave, and never leave it.
  const token = deps.getSecret(deps.githubTokenId ?? "GITHUB_TOKEN");
  const geminiApiKey = deps.getSecret(deps.geminiKeyId ?? "GEMINI_API_KEY");

  const parsed = parseRepoInput(request.repo);
  if (request.ref) parsed.ref = request.ref;

  const gh = { http: deps.http, token, apiBase: deps.githubApiBase };
  const repo = await fetchRepoMeta(parsed, gh);
  const { tree, truncated } = await fetchTree(repo, gh);
  const { contents, considered } = await fetchFiles(repo, tree, gh);

  deps.log(
    `analyzing ${repo.owner}/${repo.name}@${repo.commit.slice(0, 7)} — ` +
      `${contents.size} of ${considered} candidate files read`,
  );

  const report = await analyzeRepo(
    { repo, tree, contents, treeTruncated: truncated, filesConsidered: considered },
    {
      geminiApiKey,
      http: deps.http,
      geminiEndpointBase: deps.geminiEndpointBase,
    },
  );

  deps.log(
    `verdict "${report.verdict}" (${report.threatScore}/100) from ` +
      `${report.findings.length} findings`,
  );

  // The findings themselves stay inside. They quote repository source
  // verbatim, so emitting them to the DON would publish the private code this
  // whole arrangement exists to protect.
  return {
    repo: `${repo.owner}/${repo.name}`,
    commit: report.repo.commit,
    threatScore: report.threatScore,
    verdict: report.verdict,
    findingCount: report.findings.length,
    criticalCount: report.findings.filter(
      (f: Finding) => f.severity === "critical",
    ).length,
    scannedAt: report.timestamp,
  };
}
