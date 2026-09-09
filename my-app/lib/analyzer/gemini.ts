import type { HttpClient, HttpResponse } from "./http";
import type { Finding, Severity } from "./types";

/**
 * Phase 2 — targeted AI analysis.
 *
 * Only files that Phase 1 already flagged reach this function. That is the
 * whole point of the pipeline: a repo can be 50 000 files, but the model only
 * ever sees the handful that tripped a rule, which keeps the scan fast enough
 * to wait for and cheap enough to run for free.
 *
 * This phase fails open. A missing key, a rate limit, or malformed JSON
 * degrades the report to Phase 1 results with a note — it never fails a scan.
 */

/**
 * Model preference.
 *
 * Chosen by measurement, not by reputation. Benchmarking each candidate three
 * times against this exact payload found the flagship flash models returning
 * HTTP 503 "experiencing high demand" one to two times out of three, while the
 * lite models answered 3/3 in about two seconds. Google also retires ids on its
 * own schedule — `gemini-2.5-flash` stopped accepting new API keys mid-build.
 *
 * So the first two are raced in parallel: a strong model for analysis quality
 * and a reliable one to guarantee an answer. Whichever returns first wins, and
 * the rest are tried only if both fail. That turns a coin-flip into a near
 * certainty without waiting out a single model's backoff.
 */
const MODEL_CHAIN = [
  process.env.GEMINI_MODEL,
  "gemini-3.6-flash",
  "gemini-flash-lite-latest",
  "gemini-3.1-flash-lite",
  "gemini-3.5-flash",
].filter((m): m is string => Boolean(m));

/** How many models are raced simultaneously on the first round. */
const HEDGE_WIDTH = 2;

const DEFAULT_GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta";

const ENDPOINT = (base: string, model: string) =>
  `${base.replace(/\/$/, "")}/models/${model}:generateContent`;

const MAX_BYTES_PER_FILE = 24_000;
const MAX_TOTAL_BYTES = 120_000;
const MAX_FILES = 10;

/**
 * These are thinking models: a run that emits 236 tokens of JSON can burn 800
 * more on reasoning first, and both come out of this budget. Set too low, the
 * response is cut off mid-JSON and the whole phase is lost.
 */
const MAX_OUTPUT_TOKENS = 16_384;

const SYSTEM_PROMPT = `You are a malware analyst specialising in software supply-chain attacks, and specifically in the "Contagious Interview" campaign run by North Korean threat actors, in which developers are sent GitHub repositories disguised as job-interview coding assignments.

You are reviewing files that a static analyser has already flagged as suspicious. Your job is to determine what the code ACTUALLY DOES when executed, and to say so in plain English that a working developer with no security background can follow.

For each file, determine:
1. Does it read credentials, SSH keys, environment variables, browser extension storage, or cryptocurrency wallet files?
2. Does it open a network connection to send data out, or to receive commands?
3. Does it download or execute additional code that is not in the repository?
4. Is it obfuscated — encoded, minified, or assembled at runtime — in a way that hides intent?
5. Does it execute automatically (install hooks, editor tasks, build scripts) rather than when the developer chooses to run it?

Rules for your output:
- Describe the execution flow concretely: what runs first, what it reads, where it sends it. Name the actual paths and hosts you see in the code.
- Do NOT flag ordinary code. Build tooling, test helpers, and normal dependency installs are not attacks. A file that turns out to be benign should produce no findings — say so rather than inventing something.
- If a file is obfuscated, decode what you can and report the decoded behaviour.
- Never invent a URL, path, or capability that is not present in the code you were given.
- Severity: "critical" for credential theft, backdoors, or silent remote execution; "high" for obfuscation or exfiltration capability without confirmed intent; "medium" for risky-but-plausible patterns; "low" for hygiene issues.`;

const RESPONSE_SCHEMA = {
  type: "object",
  properties: {
    isMalicious: { type: "boolean" },
    confidence: { type: "string", enum: ["high", "medium", "low"] },
    summary: { type: "string" },
    findings: {
      type: "array",
      items: {
        type: "object",
        properties: {
          file: { type: "string" },
          severity: {
            type: "string",
            enum: ["critical", "high", "medium", "low"],
          },
          title: { type: "string" },
          executionFlow: { type: "string" },
          evidence: { type: "string" },
          recommendation: { type: "string" },
        },
        required: ["file", "severity", "title", "executionFlow", "recommendation"],
      },
    },
  },
  required: ["isMalicious", "summary", "findings"],
} as const;

export interface AIResult {
  findings: Finding[];
  summary: string | null;
  isMalicious: boolean;
  filesAnalyzed: number;
  /** Set when the phase degraded; the caller surfaces this in the report. */
  error?: string;
}

export interface FlaggedFile {
  path: string;
  content: string;
  /** Why Phase 1 flagged it — steers the model toward the right question. */
  reasons: string[];
}

export async function analyzeWithGemini(
  flagged: FlaggedFile[],
  apiKey: string,
  repoName: string,
  http: HttpClient,
  endpointBase: string = DEFAULT_GEMINI_BASE,
): Promise<AIResult> {
  const empty: AIResult = {
    findings: [],
    summary: null,
    isMalicious: false,
    filesAnalyzed: 0,
  };
  if (flagged.length === 0) return empty;

  const batch = selectBatch(flagged);
  if (batch.length === 0) return empty;

  const prompt = buildPrompt(batch, repoName);

  let raw: string;
  try {
    raw = await callGemini(prompt, apiKey, http, endpointBase);
  } catch (error) {
    return {
      ...empty,
      error: `AI analysis unavailable (${error instanceof Error ? error.message : "unknown error"}). Showing static analysis only.`,
    };
  }

  const parsed = parseResponse(raw);
  if (!parsed) {
    return {
      ...empty,
      error: "AI returned an unreadable response. Showing static analysis only.",
    };
  }

  const findings: Finding[] = parsed.findings.map((f, index) => ({
    id: `AI:${f.file}:${index}`,
    ruleId: "AI",
    severity: normalizeSeverity(f.severity),
    phase: "ai" as const,
    category: "ai-analysis",
    title: f.title,
    description: f.executionFlow,
    file: f.file,
    evidence: (f.evidence ?? "").slice(0, 600),
    recommendation: f.recommendation,
    aiExplanation: f.executionFlow,
    confirmedByAI: true,
  }));

  return {
    findings,
    summary: parsed.summary,
    isMalicious: parsed.isMalicious,
    filesAnalyzed: batch.length,
  };
}

/** Highest-risk files first, truncated to fit the byte budget. */
function selectBatch(flagged: FlaggedFile[]): FlaggedFile[] {
  const sorted = [...flagged].sort((a, b) => b.reasons.length - a.reasons.length);
  const batch: FlaggedFile[] = [];
  let total = 0;
  for (const file of sorted) {
    if (batch.length >= MAX_FILES) break;
    const content = truncate(file.content, MAX_BYTES_PER_FILE);
    if (total + content.length > MAX_TOTAL_BYTES) continue;
    total += content.length;
    batch.push({ ...file, content });
  }
  return batch;
}

/**
 * Keep both ends of a long file. Payloads hide at the bottom at least as often
 * as at the top, and a head-only truncation would miss them.
 */
function truncate(content: string, max: number): string {
  if (content.length <= max) return content;
  const half = Math.floor(max / 2);
  return `${content.slice(0, half)}\n\n… [${content.length - max} characters omitted] …\n\n${content.slice(-half)}`;
}

function buildPrompt(batch: FlaggedFile[], repoName: string): string {
  const files = batch
    .map(
      (f) =>
        `--- FILE: ${f.path} ---\nFlagged by static analysis for: ${f.reasons.join("; ")}\n\n${f.content}\n--- END FILE: ${f.path} ---`,
    )
    .join("\n\n");

  return `${SYSTEM_PROMPT}

Repository: ${repoName}
Context: this repository was sent to a developer as a job-interview coding assignment.

${files}`;
}

/**
 * Ask the first model that answers.
 *
 * `Promise.any` resolves on the first success and only rejects when every
 * candidate has failed, which is exactly the semantics wanted here — and it
 * needs no timers, so it works unchanged inside the enclave.
 */
async function callGemini(
  prompt: string,
  apiKey: string,
  http: HttpClient,
  endpointBase: string,
): Promise<string> {
  const body = buildRequestBody(prompt);

  const hedged = MODEL_CHAIN.slice(0, HEDGE_WIDTH);
  const remaining = MODEL_CHAIN.slice(HEDGE_WIDTH);

  try {
    return await Promise.any(
      hedged.map((model) => attempt(model, body, apiKey, http, endpointBase)),
    );
  } catch (error) {
    // Every hedged model failed. Fall through the rest one at a time rather
    // than firing another burst at an API that just told us it is overloaded.
    let lastError: unknown = error;
    for (const model of remaining) {
      try {
        return await attempt(model, body, apiKey, http, endpointBase);
      } catch (next) {
        lastError = next;
      }
    }
    throw normalizeError(lastError);
  }
}

async function attempt(
  model: string,
  body: string,
  apiKey: string,
  http: HttpClient,
  endpointBase: string,
): Promise<string> {
  const response = await http.send({
    url: ENDPOINT(endpointBase, model),
    method: "POST",
    headers: { "content-type": "application/json", "x-goog-api-key": apiKey },
    body,
  });
  return readResponse(model, response);
}

function buildRequestBody(prompt: string): string {
  return JSON.stringify({
    contents: [{ role: "user", parts: [{ text: prompt }] }],
    generationConfig: {
      temperature: 0.1,
      maxOutputTokens: MAX_OUTPUT_TOKENS,
      responseMimeType: "application/json",
      responseSchema: RESPONSE_SCHEMA,
    },
    safetySettings: [
      // The input is malware by design; the default filters would refuse it.
      "HARM_CATEGORY_DANGEROUS_CONTENT",
      "HARM_CATEGORY_HARASSMENT",
      "HARM_CATEGORY_HATE_SPEECH",
      "HARM_CATEGORY_SEXUALLY_EXPLICIT",
    ].map((category) => ({ category, threshold: "BLOCK_NONE" })),
  });
}

function readResponse(model: string, response: HttpResponse): string {
  if (response.status !== 200) {
    const detail = response.body?.slice(0, 160) ?? "";
    throw new Error(`${model}: HTTP ${response.status}${detail ? ` ${detail}` : ""}`);
  }

  let json: {
    candidates?: {
      finishReason?: string;
      content?: { parts?: { text?: string }[] };
    }[];
    promptFeedback?: { blockReason?: string };
  };
  try {
    json = JSON.parse(response.body);
  } catch {
    throw new Error(`${model}: response was not JSON`);
  }

  if (json.promptFeedback?.blockReason) {
    throw new Error(`${model}: blocked (${json.promptFeedback.blockReason})`);
  }

  const candidate = json.candidates?.[0];
  if (candidate?.finishReason === "MAX_TOKENS") {
    // The JSON is cut off mid-object; parsing it would silently drop findings.
    throw new Error(`${model}: response exceeded the output budget`);
  }

  const text = candidate?.content?.parts?.[0]?.text;
  if (!text) throw new Error(`${model}: empty response`);
  return text;
}

/** `Promise.any` rejects with an AggregateError; surface something readable. */
function normalizeError(error: unknown): Error {
  if (error instanceof AggregateError) {
    const reasons = error.errors
      .map((e) => (e instanceof Error ? e.message : String(e)))
      .join("; ");
    return new Error(reasons || "all models failed");
  }
  return error instanceof Error ? error : new Error(String(error));
}

interface ParsedResponse {
  isMalicious: boolean;
  summary: string;
  findings: {
    file: string;
    severity: string;
    title: string;
    executionFlow: string;
    evidence?: string;
    recommendation: string;
  }[];
}

function parseResponse(raw: string): ParsedResponse | null {
  const attempt = (text: string) => {
    try {
      const parsed = JSON.parse(text) as ParsedResponse;
      if (!Array.isArray(parsed.findings)) return null;
      return parsed;
    } catch {
      return null;
    }
  };

  // Schema-constrained output should be clean JSON, but a fenced block or
  // leading prose costs one regex to survive and saves the whole phase.
  return (
    attempt(raw) ??
    attempt(raw.replace(/^```(?:json)?\s*|\s*```$/g, "")) ??
    attempt(raw.slice(raw.indexOf("{"), raw.lastIndexOf("}") + 1))
  );
}

function normalizeSeverity(value: string): Severity {
  const allowed: Severity[] = ["critical", "high", "medium", "low", "info"];
  const normalized = value?.toLowerCase() as Severity;
  return allowed.includes(normalized) ? normalized : "medium";
}
