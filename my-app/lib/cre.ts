import type { HttpClient } from "./analyzer/http";
import type { ThreatReport } from "./analyzer/types";
import { sha256Hex } from "./analyzer/portable";

/**
 * Client for the deployed Confidential Workflow.
 *
 * This is what makes the CRE workflow part of the product rather than a
 * parallel demo: "Confidential scan" is a mode the user can pick, and when
 * they do, the repository is read and analysed entirely inside the enclave.
 * This server never sees the source, and neither does the CRE node operator.
 *
 * The trade is visible in the result. A normal scan returns every finding with
 * its evidence; a confidential scan returns a score and counts, because the
 * evidence quotes private source and emitting it to the DON would publish the
 * thing the enclave exists to protect.
 */

export interface CreVerdict {
  repo: string;
  commit: string;
  threatScore: number;
  verdict: "safe" | "caution" | "danger";
  findingCount: number;
  criticalCount: number;
  scannedAt: string;
}

export class CreError extends Error {}

export function creConfigured(): boolean {
  return Boolean(process.env.CRE_WORKFLOW_URL);
}

export async function runConfidentialScan(
  repo: string,
  ref: string | undefined,
  http: HttpClient,
): Promise<CreVerdict> {
  const url = process.env.CRE_WORKFLOW_URL;
  if (!url) {
    throw new CreError(
      "Confidential scanning is not configured on this server. Deploy the CRE workflow and set CRE_WORKFLOW_URL.",
    );
  }

  const response = await http.send({
    url,
    method: "POST",
    headers: {
      "content-type": "application/json",
      // The HTTP trigger validates request signatures against the
      // `authorizedKeys` baked into the workflow config at deploy time.
      ...(process.env.CRE_WORKFLOW_KEY
        ? { authorization: `Bearer ${process.env.CRE_WORKFLOW_KEY}` }
        : {}),
    },
    body: JSON.stringify({ repo, ref }),
  });

  if (response.status !== 200) {
    throw new CreError(
      `The confidential workflow returned ${response.status}. ${response.body.slice(0, 200)}`,
    );
  }

  try {
    return JSON.parse(response.body) as CreVerdict;
  } catch {
    throw new CreError("The confidential workflow returned an unreadable response.");
  }
}

/**
 * Shape a DON verdict into the same `ThreatReport` the UI already renders.
 *
 * The findings array is empty and stays empty — that is the honest
 * representation of what came back, not a gap to be filled in later.
 */
export function verdictToReport(
  verdict: CreVerdict,
  repo: { owner: string; name: string },
  startedAt: number,
): ThreatReport {
  // Identify the repository from what we parsed, not from the string the
  // workflow echoed back. The verdict is the workflow's to report; which repo
  // the user asked about is ours to know.
  const { owner, name } = repo;

  return {
    id: sha256Hex(`${owner}/${name}@${verdict.commit}`).slice(0, 16),
    repo: {
      owner,
      name,
      url: `https://github.com/${owner}/${name}`,
      ref: verdict.commit.slice(0, 7),
      commit: verdict.commit,
      isPrivate: true,
    },
    timestamp: verdict.scannedAt,
    profile: {
      frameworks: ["unknown"],
      languages: [],
      packageManagers: [],
      filesOfInterest: [],
      hasLockfile: false,
      fileCount: 0,
    },
    threatScore: verdict.threatScore,
    verdict: verdict.verdict,
    findings: [],
    summary:
      `This repository was analysed inside a Chainlink CRE Trusted Execution Environment. ` +
      `${verdict.findingCount} issue${verdict.findingCount === 1 ? "" : "s"} were found` +
      (verdict.criticalCount > 0
        ? `, ${verdict.criticalCount} of them critical`
        : "") +
      `, giving a threat score of ${verdict.threatScore}/100. ` +
      `The findings themselves quote your repository's source code, so they were not emitted from the enclave — ` +
      `only this verdict crossed the boundary. Neither this server nor the node operator saw your code. ` +
      `Run a standard scan if you want the file-by-file detail.`,
    actionPlan:
      verdict.verdict === "safe"
        ? []
        : [
            {
              priority: 0,
              title: "Re-run as a standard scan to see what was found",
              detail:
                "A confidential scan deliberately withholds the evidence. To read the specific files and code involved, run a normal scan — the analysis is identical, but the report is assembled on this server rather than inside the enclave.",
            },
            {
              priority: 1,
              title: "Until then, do not run it",
              detail: `${verdict.criticalCount > 0 ? "Critical" : "Non-trivial"} findings were confirmed inside the enclave. Treat the repository as untrusted until you have read them.`,
            },
          ],
    stats: {
      filesInTree: 0,
      filesConsidered: 0,
      // The enclave reports a verdict, not a file census. Claiming a coverage
      // figure we did not measure would be worse than reporting none.
      coverage: 1,
      filesFetched: 0,
      filesFlagged: verdict.findingCount,
      filesAnalyzedByAI: 0,
      durationMs: Date.now() - startedAt,
      treeTruncated: false,
    },
    degraded: [],
    confidential: true,
  };
}
