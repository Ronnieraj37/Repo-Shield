import { analyzeRepo } from "@/lib/analyzer";
import type { ScanEvent } from "@/lib/analyzer/types";
import {
  GitHubError,
  fetchFiles,
  fetchRepoMeta,
  fetchTree,
  parseRepoInput,
} from "@/lib/github";
import { getSample, sampleToAnalyzeInput } from "@/lib/samples";
import {
  CreError,
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
  let body: ScanRequest;
  try {
    body = (await request.json()) as ScanRequest;
  } catch {
    return Response.json({ error: "Malformed request." }, { status: 400 });
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

  const repo = await fetchRepoMeta(parsed, { http, token });

  send({
    type: "stage",
    stage: "tree",
    message: "Reading the file tree",
    detail: `${repo.ref} at ${repo.commit.slice(0, 7)}`,
  });
  const { tree, truncated } = await fetchTree(repo, { http, token });

  send({
    type: "stage",
    stage: "fetching",
    message: "Fetching files worth reading",
    detail: `${tree.filter((e) => e.type === "blob").length} files in tree`,
  });
  const { contents, considered } = await fetchFiles(repo, tree, { http, token }, (fetched, total) => {
    // Only report at intervals; one event per file would flood the stream for
    // no benefit at these speeds.
    if (fetched === total || fetched % 5 === 0) {
      send({
        type: "stage",
        stage: "fetching",
        message: "Fetching files worth reading",
        detail: `${fetched} of ${total}`,
      });
    }
  });

  const report = await analyzeRepo(
    { repo, tree, contents, treeTruncated: truncated, filesConsidered: considered },
    { geminiApiKey, http, onEvent: send },
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
