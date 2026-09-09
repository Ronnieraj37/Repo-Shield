import type { FileEntry, RepoMeta } from "./analyzer/types";
import {
  findReferencedFiles,
  selectFilesWithCoverage,
} from "./analyzer/detector";
import type { HttpClient } from "./analyzer/http";
import { base64ToBytes, looksBinary, utf8Decode } from "./analyzer/portable";

const DEFAULT_API = "https://api.github.com";

export type GitHubErrorCode =
  | "INVALID_INPUT"
  | "NOT_FOUND"
  | "NEEDS_AUTH"
  | "FORBIDDEN"
  | "RATE_LIMITED"
  | "TOO_LARGE"
  | "NETWORK";

/**
 * Typed failures, because the difference between "this repo does not exist"
 * and "this repo exists but you cannot see it" is the entire product. The
 * second one is the prompt to sign in; the first one never should be.
 */
export class GitHubError extends Error {
  constructor(
    readonly code: GitHubErrorCode,
    message: string,
    readonly retryAt?: Date,
  ) {
    super(message);
    this.name = "GitHubError";
  }
}

export interface ParsedRepoInput {
  owner: string;
  name: string;
  /** Branch, tag, or SHA if the input carried one. */
  ref?: string;
}

/**
 * Accept whatever the developer pasted.
 *
 * Someone who has just been sent a suspicious link will paste the whole URL,
 * with the `/tree/branch` suffix, or the SSH clone string, or just
 * `owner/repo` from memory. Rejecting any of those is a pointless failure.
 */
export function parseRepoInput(raw: string): ParsedRepoInput {
  const input = raw.trim();
  if (!input) throw new GitHubError("INVALID_INPUT", "Enter a repository.");

  const patterns: RegExp[] = [
    // https://github.com/owner/repo(/tree/ref)(.git)
    /^(?:https?:\/\/)?(?:www\.)?github\.com\/([\w.-]+)\/([\w.-]+?)(?:\.git)?(?:\/(?:tree|commit|blob)\/([^/\s?#]+))?(?:[/?#].*)?$/i,
    // git@github.com:owner/repo.git
    /^git@github\.com:([\w.-]+)\/([\w.-]+?)(?:\.git)?$/i,
    // owner/repo
    /^([\w.-]+)\/([\w.-]+?)(?:\.git)?$/,
  ];

  for (const pattern of patterns) {
    const match = input.match(pattern);
    if (!match) continue;
    const [, owner, name, ref] = match;
    if (owner === "." || name === ".") continue;
    return { owner, name, ref: ref || undefined };
  }

  throw new GitHubError(
    "INVALID_INPUT",
    "That does not look like a GitHub repository. Try a URL like github.com/owner/repo, or just owner/repo.",
  );
}

/**
 * Every call needs a transport and, optionally, a token.
 *
 * `http` is required rather than defaulting to `fetch`: this module is
 * imported by the CRE workflow, which compiles to WASM where `fetch` does not
 * exist. A default would either pull dead transport code into that bundle or
 * fail at runtime in the one environment hardest to debug.
 */
export interface GitHubOptions {
  http: HttpClient;
  token?: string;
  /**
   * API origin. Overridable so a CRE simulation can point at a local mock
   * server — the CLI simulator has no route to the real internet.
   */
  apiBase?: string;
}

interface RequestOptions extends GitHubOptions {
  /** Treat 404 as null rather than throwing (used to probe visibility). */
  allowMissing?: boolean;
}

async function request<T>(
  path: string,
  { token, allowMissing, http, apiBase }: RequestOptions,
): Promise<T | null> {
  const response = await http.send({
    url: `${(apiBase ?? DEFAULT_API).replace(/\/$/, "")}${path}`,
    method: "GET",
    headers: {
      accept: "application/vnd.github+json",
      "x-github-api-version": "2022-11-28",
      "user-agent": "RepoShield",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
  });

  if (response.status === 599) {
    throw new GitHubError("NETWORK", "Could not reach GitHub.");
  }

  if (response.status >= 200 && response.status < 300) {
    try {
      return JSON.parse(response.body) as T;
    } catch {
      throw new GitHubError("NETWORK", "GitHub returned a malformed response.");
    }
  }

  const remaining = response.headers?.["x-ratelimit-remaining"];
  const reset = response.headers?.["x-ratelimit-reset"];

  if ((response.status === 403 || response.status === 429) && remaining === "0") {
    const retryAt = reset ? new Date(Number(reset) * 1000) : undefined;
    throw new GitHubError(
      "RATE_LIMITED",
      token
        ? "GitHub's API rate limit is exhausted for this account. It resets shortly."
        : "GitHub's anonymous rate limit is exhausted for your network. Sign in with GitHub to get your own, much larger limit.",
      retryAt,
    );
  }

  if (response.status === 404) {
    if (allowMissing) return null;
    // GitHub returns 404, not 403, for private repos you cannot see — it
    // refuses to confirm they exist. So a 404 without a token is ambiguous,
    // and the honest message says so.
    throw new GitHubError(
      token ? "NOT_FOUND" : "NEEDS_AUTH",
      token
        ? "That repository does not exist, or your account cannot see it."
        : "This repository is either private or does not exist. Sign in with GitHub to check.",
    );
  }

  if (response.status === 401) {
    throw new GitHubError(
      "NEEDS_AUTH",
      "Your GitHub session has expired. Sign in again.",
    );
  }

  if (response.status === 403) {
    throw new GitHubError("FORBIDDEN", "GitHub refused this request.");
  }

  throw new GitHubError("NETWORK", `GitHub returned ${response.status}.`);
}

interface RepoResponse {
  name: string;
  owner: { login: string };
  html_url: string;
  private: boolean;
  default_branch: string;
  stargazers_count: number;
  pushed_at: string;
  size: number;
}

export async function fetchRepoMeta(
  input: ParsedRepoInput,
  options: GitHubOptions,
): Promise<RepoMeta> {
  const repo = await request<RepoResponse>(
    `/repos/${input.owner}/${input.name}`,
    options,
  );
  if (!repo) throw new GitHubError("NOT_FOUND", "Repository not found.");

  const ref = input.ref ?? repo.default_branch;
  const commit = await resolveRef(input.owner, input.name, ref, options);

  return {
    owner: repo.owner.login,
    name: repo.name,
    url: repo.html_url,
    ref,
    commit,
    isPrivate: repo.private,
    stars: repo.stargazers_count,
    pushedAt: repo.pushed_at,
    defaultBranch: repo.default_branch,
  };
}

/**
 * Pin the scan to a commit SHA.
 *
 * Reports are keyed by commit, so a report stays true to what was actually
 * analysed. If the repo owner force-pushes after you scanned, that is a new
 * commit and a new report — not a silently invalidated old one.
 */
async function resolveRef(
  owner: string,
  name: string,
  ref: string,
  options: GitHubOptions,
): Promise<string> {
  if (/^[0-9a-f]{40}$/i.test(ref)) return ref;
  const commit = await request<{ sha: string }>(
    `/repos/${owner}/${name}/commits/${encodeURIComponent(ref)}`,
    options,
  );
  if (!commit) throw new GitHubError("NOT_FOUND", `Ref "${ref}" not found.`);
  return commit.sha;
}

interface TreeResponse {
  tree: { path: string; type: string; size?: number }[];
  truncated: boolean;
}

export async function fetchTree(
  repo: RepoMeta,
  options: GitHubOptions,
): Promise<{ tree: FileEntry[]; truncated: boolean }> {
  const data = await request<TreeResponse>(
    `/repos/${repo.owner}/${repo.name}/git/trees/${repo.commit}?recursive=1`,
    options,
  );
  if (!data) throw new GitHubError("NOT_FOUND", "Could not read the file tree.");

  return {
    tree: data.tree
      .filter((e) => e.type === "blob" || e.type === "tree")
      .map((e) => ({
        path: e.path,
        type: e.type as "blob" | "tree",
        size: e.size,
      })),
    // A truncated tree means we may not have seen every file. The UI says so
    // rather than implying full coverage.
    truncated: data.truncated,
  };
}

const MAX_FILE_BYTES = 400_000;
const FETCH_CONCURRENCY = 8;

/**
 * Fetch the files the detector asked for, in parallel, within a budget.
 *
 * Every file is one API call against a shared rate limit, so this is capped
 * rather than exhaustive. `selectFilesToFetch` has already ordered them by
 * risk, so a truncated fetch still gets the dangerous files.
 */
export async function fetchFiles(
  repo: RepoMeta,
  tree: FileEntry[],
  options: GitHubOptions,
  onProgress?: (fetched: number, total: number) => void,
): Promise<{ contents: Map<string, string>; considered: number }> {
  const { selected: wanted, considered } = selectFilesWithCoverage(tree);
  const contents = new Map<string, string>();
  let completed = 0;
  let total = wanted.length;

  const drain = async (entries: FileEntry[]) => {
    const queue = [...entries];
    const workers = Array.from(
      { length: Math.min(FETCH_CONCURRENCY, queue.length) },
      async () => {
        for (;;) {
          const entry = queue.shift();
          if (!entry) return;
          const text = await fetchBlob(repo, entry, options);
          if (text !== null) contents.set(entry.path, text);
          onProgress?.(++completed, total);
        }
      },
    );
    await Promise.all(workers);
  };

  await drain(wanted);

  // Second pass: pull in the scripts the configs actually point at. Without
  // this we report that `.vscode/tasks.json` auto-runs a file and then never
  // read that file — which is where the payload lives.
  const byPath = new Map(tree.filter((e) => e.type === "blob").map((e) => [e.path, e]));
  const referenced = findReferencedFiles(contents, tree, new Set(contents.keys()))
    .map((path) => byPath.get(path))
    .filter((entry): entry is FileEntry => Boolean(entry));

  if (referenced.length > 0) {
    total += referenced.length;
    await drain(referenced);
  }

  return { contents, considered };
}

async function fetchBlob(
  repo: RepoMeta,
  entry: FileEntry,
  options: GitHubOptions,
): Promise<string | null> {
  if ((entry.size ?? 0) > MAX_FILE_BYTES) return null;

  let data: { content?: string; encoding?: string } | null;
  try {
    data = await request<{ content?: string; encoding?: string }>(
      `/repos/${repo.owner}/${repo.name}/contents/${encodePath(entry.path)}?ref=${repo.commit}`,
      { ...options, allowMissing: true },
    );
  } catch (error) {
    // One unreadable file must not fail the scan; the rest still get analysed.
    if (error instanceof GitHubError && error.code === "RATE_LIMITED") throw error;
    return null;
  }

  if (!data?.content || data.encoding !== "base64") return null;

  // Decoded with the portable helpers rather than `Buffer`, which the CRE
  // WASM runtime does not provide.
  const bytes = base64ToBytes(data.content);
  // A NUL byte in the first kilobyte means it isn't text. Binaries are flagged
  // by R25 from the tree alone; decoding them is wasted work.
  if (looksBinary(bytes)) return null;
  return utf8Decode(bytes);
}

function encodePath(path: string): string {
  return path.split("/").map(encodeURIComponent).join("/");
}

export interface RepoSummary {
  fullName: string;
  url: string;
  isPrivate: boolean;
  pushedAt: string;
  description: string | null;
  /** True when the signed-in user does not own it — i.e. they were invited. */
  isCollaboration: boolean;
}

/**
 * Repos the signed-in user can read, most recently pushed first.
 *
 * Sorting by `pushed_at` is the point: the repository a "recruiter" just
 * invited you to is the one at the top of this list. Finding it should not
 * require pasting a URL.
 */
export async function listAccessibleRepos(
  login: string,
  options: GitHubOptions,
): Promise<RepoSummary[]> {
  const repos = await request<
    {
      full_name: string;
      html_url: string;
      private: boolean;
      pushed_at: string;
      description: string | null;
      owner: { login: string };
    }[]
  >(
    "/user/repos?per_page=50&sort=pushed&affiliation=owner,collaborator,organization_member",
    options,
  );

  return (repos ?? []).map((r) => ({
    fullName: r.full_name,
    url: r.html_url,
    isPrivate: r.private,
    pushedAt: r.pushed_at,
    description: r.description,
    isCollaboration: r.owner.login.toLowerCase() !== login.toLowerCase(),
  }));
}

export interface GitHubUser {
  login: string;
  name: string | null;
  avatarUrl: string;
}

export async function fetchViewer(options: GitHubOptions): Promise<GitHubUser> {
  const user = await request<{
    login: string;
    name: string | null;
    avatar_url: string;
  }>("/user", options);
  if (!user) throw new GitHubError("NEEDS_AUTH", "Could not read your GitHub profile.");
  return { login: user.login, name: user.name, avatarUrl: user.avatar_url };
}

/** Remaining anonymous/authenticated API budget, for the pre-scan hint. */
export async function fetchRateLimit(
  options: GitHubOptions,
): Promise<{ remaining: number; limit: number; resetAt: string } | null> {
  try {
    const data = await request<{
      resources: { core: { remaining: number; limit: number; reset: number } };
    }>("/rate_limit", options);
    if (!data) return null;
    const core = data.resources.core;
    return {
      remaining: core.remaining,
      limit: core.limit,
      resetAt: new Date(core.reset * 1000).toISOString(),
    };
  } catch {
    return null;
  }
}
