import type { HttpClient, HttpRequest, HttpResponse } from "./analyzer/http";

/**
 * The `fetch`-backed HTTP client used by the web app.
 *
 * All the things the CRE runtime cannot do — timeouts, retries, backoff —
 * live here rather than in the analyzer, so the engine stays portable.
 */

const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_ATTEMPTS = 2;

export interface FetchClientOptions {
  timeoutMs?: number;
  /** Attempts per request, including the first. Transient failures only. */
  maxAttempts?: number;
}

export function createFetchClient(options: FetchClientOptions = {}): HttpClient {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxAttempts = options.maxAttempts ?? MAX_ATTEMPTS;

  return {
    async send(request: HttpRequest): Promise<HttpResponse> {
      let lastError: unknown;

      for (let attempt = 0; attempt < maxAttempts; attempt++) {
        if (attempt > 0) {
          // Short jittered backoff. The caller is already racing several
          // models, so this only needs to cover a brief blip.
          await sleep(600 * attempt * (0.75 + Math.random() * 0.5));
        }

        try {
          const response = await withTimeout(request, timeoutMs);
          // 5xx and 429 are worth one more try; everything else is the answer,
          // including 4xx — retrying a bad request just wastes the budget.
          if (response.status >= 500 || response.status === 429) {
            lastError = new Error(`HTTP ${response.status}`);
            continue;
          }
          return response;
        } catch (error) {
          lastError = error;
        }
      }

      // Surface the failure as a response rather than throwing, so callers
      // interpret transport errors and HTTP errors through one code path.
      return {
        status: 599,
        body: lastError instanceof Error ? lastError.message : "request failed",
      };
    },
  };
}

async function withTimeout(
  request: HttpRequest,
  timeoutMs: number,
): Promise<HttpResponse> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(request.url, {
      method: request.method ?? "GET",
      headers: request.headers,
      body: request.body,
      signal: controller.signal,
      cache: "no-store",
      redirect: request.followRedirects === false ? "manual" : "follow",
    });
    const headers = Object.fromEntries(response.headers.entries());
    if (request.responseType === "bytes") {
      return {
        status: response.status,
        body: "",
        bytes: new Uint8Array(await response.arrayBuffer()),
        headers,
      };
    }
    return { status: response.status, body: await response.text(), headers };
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      throw new Error(`timed out after ${Math.round(timeoutMs / 1000)}s`);
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
