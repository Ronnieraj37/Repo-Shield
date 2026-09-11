import { analyzeRepo } from "@/lib/analyzer";
import type { FileEntry, ScanEvent } from "@/lib/analyzer/types";
import {
  GitHubError,
  fetchFiles,
  fetchRepoMeta,
  fetchTree,
  parseRepoInput,
} from "@/lib/github";
import { fetchRepoArchive } from "@/lib/github-archive";
import { gatherPriorFlags } from "@/lib/graph";
import { fetchPublicRepo } from "@/lib/providers";
import { getSample, sampleToAnalyzeInput } from "@/lib/samples";
import {
  CreError,
  creConfigured,
  runConfidentialScan,
  verdictToReport,
} from "@/lib/cre";
import { createFetchClient } from "@/lib/http-fetch";
import { resolveToken } from "@/lib/session";

export const runtime = "nodejs";
// Every scan reads live repository state; a cached scan result would be worse
// than useless, since the whole question is what the code says right now.
export const dynamic = "force-dynamic";

interface ScanRequest {
  repo?: string;
  /** A token the developer pasted for this one request. Never stored. */
  token?: string;
  /** Slug of a bundled sample instead of a live repo. */
  sample?: string;
  /**
   * "confidential" routes the whole analysis through the CRE enclave, so this
   * server never sees the repository. Defaults to a local scan.
   */
  mode?: "local" | "confidential";
}

export async function POST(request: Request) {
  // A malformed body still gets answered as an event stream. Returning a bare
  // 400 here leaves the client's SSE reader with nothing to parse, so the scan
  // sits on "running" forever instead of showing the error.
  let body: ScanRequest | null = null;
  let parseError: string | null = null;
  try {
    body = (await request.json()) as ScanRequest;
  } catch {
    parseError = "The scan request could not be read. Please try again.";
  }

  const encoder = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      const send = (event: ScanEvent) => {
        try {
          controller.enqueue(encoder.encode(`data: ${JSON.stringify(event)}\n\n`));
        } catch {
          // Client disconnected mid-scan; nothing to do but stop writing.
        }
      };

      try {
        if (parseError || !body) {
          send({ type: "error", code: "INVALID_INPUT", message: parseError ?? "Empty request." });
          return;
        }
        await runScan(body, send);
      } catch (error) {
        send(toErrorEvent(error));
      } finally {
        controller.close();
      }
    },
  });

  return new Response(stream, {
    headers: {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-cache, no-transform",
      connection: "keep-alive",
      // Nginx and friends buffer streamed responses by default, which would
      // turn live progress back into a single blob at the end.
      "x-accel-buffering": "no",
    },
  });
}

async function runScan(body: ScanRequest, send: (event: ScanEvent) => void) {
  const geminiApiKey = process.env.GEMINI_API_KEY;
  const geminiModel = process.env.GEMINI_MODEL;
  const http = createFetchClient();

  // --- Bundled sample: same pipeline, no network ---------------------------
  if (body.sample) {
    const sample = getSample(body.sample);
    if (!sample) {
      send({ type: "error", code: "NOT_FOUND", message: "Unknown sample." });
      return;
    }
    send({
      type: "stage",
      stage: "fetching",
      message: "Loading bundled sample",
      detail: sample.label,
    });
    const report = await analyzeRepo(sampleToAnalyzeInput(sample), {
      geminiApiKey,
      geminiModel,
      http,
      onEvent: send,
    });
    send({ type: "done", report });
    return;
  }

  if (!body.repo?.trim()) {
    send({ type: "error", code: "INVALID_INPUT", message: "Enter a repository." });
    return;
  }

  const parsed = parseRepoInput(body.repo);

  // --- Confidential mode: hand the whole job to the enclave ----------------
  if (body.mode === "confidential") {
    // Check the workflow is actually reachable before narrating a TEE scan.
    // Telling someone their code is being analysed in an enclave and then
    // failing is worse than failing immediately.
    if (!creConfigured()) {
      throw new CreError(
        "Confidential scanning is not configured on this server, so this scan did not run. Run a standard scan instead.",
      );
    }

    const startedAt = Date.now();
    send({
      type: "stage",
      stage: "resolving",
      message: "Handing the scan to the CRE enclave",
      detail: `${parsed.owner}/${parsed.name}`,
    });
    send({
      type: "stage",
      stage: "ai",
      message: "Analysing inside the Trusted Execution Environment",
      detail: "this server never sees the source",
    });

    const verdict = await runConfidentialScan(body.repo, parsed.ref, http);

    send({ type: "stage", stage: "scoring", message: "Verdict returned from the DON" });
    send({
      type: "done",
      report: verdictToReport(verdict, parsed, startedAt),
    });
    return;
  }

  // --- GitLab / Bitbucket: public repos only, via their archive endpoints ---
  if (parsed.host !== "github") {
    const label = parsed.host === "gitlab" ? "GitLab" : "Bitbucket";
    send({
      type: "stage",
      stage: "resolving",
      message: `Resolving ${parsed.owner}/${parsed.name}`,
      detail: `${label} · public access`,
    });
    const result = await fetchPublicRepo(parsed.host, parsed.owner, parsed.name, parsed.ref, http);
    if (!result) {
      send({
        type: "error",
        code: "TOO_LARGE",
        message: `Could not read this ${label} repository — it may be too large, or the branch was not found.`,
      });
      return;
    }
    send({
      type: "stage",
      stage: "fetching",
      message: "Fetched the repository",
      detail: `${(result.archiveBytes / 1024).toFixed(0)} KB · ${result.contents.size} files readable`,
    });

    const priorFlags = await gatherPriorFlags(result.repo.owner, result.repo.name);
    const report = await analyzeRepo(
      {
        repo: result.repo,
        tree: result.tree,
        contents: result.contents,
        filesConsidered: result.considered,
      },
      { geminiApiKey, geminiModel, http, priorFlags: priorFlags ?? undefined, onEvent: send },
    );
    send({ type: "done", report });
    return;
  }

  const { token, source } = await resolveToken(body.token);

  send({
    type: "stage",
    stage: "resolving",
    message: `Resolving ${parsed.owner}/${parsed.name}`,
    detail:
      source === "anonymous"
        ? "Public access, not signed in"
        : source === "pasted"
          ? "Using the token you pasted"
          : source === "session"
            ? "Using your GitHub session"
            : "Using this server's public API budget",
  });

  const gh = { http, token, tokenSource: source };
  const repo = await fetchRepoMeta(parsed, gh);

  // Try the archive first. It is one request that costs no API quota at all —
  // the endpoint redirects to codeload.github.com, which is not metered — and
  // it returns the file list as well as the contents. Getting the tree from it
  // means never calling the tree API, so a whole scan costs two requests
  // rather than the fifteen-plus that per-file fetching needed.
  send({
    type: "stage",
    stage: "tree",
    message: "Downloading the repository",
    detail: `${repo.ref} at ${repo.commit.slice(0, 7)}`,
  });

  let tree: FileEntry[];
  let truncated = false;
  let contents: Map<string, string>;
  let considered: number;

  const archive = await fetchRepoArchive(repo, gh, repo.sizeKb);

  if (archive) {
    tree = archive.tree;
    contents = archive.contents;
    considered = archive.considered;
    send({
      type: "stage",
      stage: "fetching",
      message: "Downloaded the whole repository in one request",
      detail: `${(archive.archiveBytes / 1024).toFixed(0)} KB · ${contents.size} files readable · no API quota used`,
    });
  } else {
    // Too large, or the archive route was unavailable. Fall back to reading
    // the tree and fetching the highest-risk files one at a time.
    send({
      type: "stage",
      stage: "tree",
      message: "Reading the file tree",
      detail: "archive unavailable, falling back to per-file",
    });
    const treeResult = await fetchTree(repo, gh);
    tree = treeResult.tree;
    truncated = treeResult.truncated;

    const result = await fetchFiles(repo, tree, gh, (fetched, total) => {
      // Only report at intervals; one event per file would flood the stream.
      if (fetched === total || fetched % 5 === 0) {
        send({
          type: "stage",
          stage: "fetching",
          message: "Fetching files worth reading",
          detail: `${fetched} of ${total}`,
        });
      }
    });
    contents = result.contents;
    considered = result.considered;
  }

  // Read what the community already knows about this repo and its owner, so the
  // AI weighs it and the report reflects it. A read-only query to The Graph;
  // it never blocks or fails the scan.
  send({
    type: "stage",
    stage: "static",
    message: "Checking the community registry",
    detail: "via The Graph",
  });
  const priorFlags = await gatherPriorFlags(repo.owner, repo.name);

  const report = await analyzeRepo(
    { repo, tree, contents, treeTruncated: truncated, filesConsidered: considered },
    { geminiApiKey, geminiModel, http, priorFlags: priorFlags ?? undefined, onEvent: send },
  );

  send({ type: "done", report });
}

function toErrorEvent(error: unknown): ScanEvent {
  if (error instanceof CreError) {
    return { type: "error", code: "CRE_UNAVAILABLE", message: error.message };
  }
  if (error instanceof GitHubError) {
    return { type: "error", code: error.code, message: error.message };
  }
  console.error("[scan] unexpected failure", error);
  return {
    type: "error",
    code: "INTERNAL",
    message: "Something went wrong during the scan. Please try again.",
  };
}
