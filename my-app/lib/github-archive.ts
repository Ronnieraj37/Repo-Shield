import type { HttpClient } from "./analyzer/http";
import { looksBinary, utf8Decode } from "./analyzer/portable";
import { GitHubError } from "./github";
import { extractTarGz } from "./tar";
import type { FileEntry, RepoMeta } from "./analyzer/types";

/**
 * Fetch a whole repository in one request that costs nothing.
 *
 * The per-file contents API costs one request each, and GitHub's anonymous
 * limit is 60 an hour per IP — so a thirty-file repo burned half an hour's
 * budget for everyone sharing the server's address.
 *
 * The tarball endpoint is better than "one request instead of thirty": it
 * 302-redirects to codeload.github.com, which is **not metered against the API
 * quota at all**. Measured against expressjs/express: the whole repository
 * arrives in 133 KB and the quota counter does not move.
 *
 * That changes what is worth analysing. When reading a file cost a request, it
 * was right to rank files by risk and read the top 70. Now every file is
 * already on disk, so the only remaining cost is CPU — and skipping files
 * would trade detection for nothing.
 *
 * Node-only, because it needs zlib. The CRE workflow keeps the per-file path:
 * it runs one scan per invocation on the user's own 5,000/hour budget, where
 * request count is irrelevant.
 */

/**
 * A loose upper bound, not a real limit.
 *
 * `repo.size` is the size of the git repository *including all history*, which
 * says very little about one commit: ethers.js reports 181 MB and its tarball
 * is 10 MB. Gating tightly on it rejected repositories that would have been
 * cheap to scan. The working tree can never exceed the git size, so this only
 * rules out the genuinely enormous — the real limit is on the download itself.
 */
const MAX_REPO_KB = 400_000;
const MAX_ARCHIVE_BYTES = 90 * 1024 * 1024;
/** Analysing more than this much text buys nothing and costs seconds. */
export const MAX_TEXT_BYTES = 24 * 1024 * 1024;
export const MAX_FILE_BYTES = 400_000;

/**
 * Vendored and generated trees. Their contents are not the repo author's code,
 * and a committed `node_modules` would otherwise dominate every scan.
 */
const IGNORED = /(^|\/)(node_modules|\.git|vendor|target|dist|build|out|coverage|artifacts|cache|\.next|__pycache__)\//;

/** Extensions worth decoding. Everything else is data, media, or a binary. */
const ANALYSABLE =
  /\.(js|cjs|mjs|jsx|ts|tsx|mts|cts|py|rb|go|rs|sol|vy|sh|bash|zsh|ps1|bat|cmd|json|jsonc|ya?ml|toml|ini|cfg|conf|env|md|mdx|txt|svg|html|htm|xml|gradle|properties|lock|makefile|dockerfile|gitattributes|npmrc|yarnrc)$/i;

/** Extensionless files that matter. */
const ANALYSABLE_NAMES =
  /(^|\/)(Makefile|Dockerfile|justfile|Justfile|Procfile|Rakefile|Gemfile|Pipfile|BUILD|WORKSPACE|\.npmrc|\.yarnrc|\.gitattributes|\.gitmodules|\.env[^/]*)$/;

export interface ArchiveResult {
  contents: Map<string, string>;
  /** Every blob in the archive, so callers need not fetch the tree API. */
  tree: FileEntry[];
  considered: number;
  archiveBytes: number;
}

export function isAnalysable(path: string): boolean {
  if (IGNORED.test(path)) return false;
  return ANALYSABLE.test(path) || ANALYSABLE_NAMES.test(path);
}

export async function fetchRepoArchive(
  repo: RepoMeta,
  options: { http: HttpClient; token?: string; apiBase?: string },
  sizeKb?: number,
): Promise<ArchiveResult | null> {
  if (typeof sizeKb === "number" && sizeKb > MAX_REPO_KB) return null;

  const base = (options.apiBase ?? "https://api.github.com").replace(/\/$/, "");
  const url = `${base}/repos/${repo.owner}/${repo.name}/tarball/${repo.commit}`;

  // Two hops, deliberately separated.
  //
  // The API endpoint answers with a 302 to a pre-signed codeload.github.com
  // URL. The token authorises that first hop and must not be sent on the
  // second: codeload does not want it, and runtimes strip `Authorization`
  // across an origin change regardless — which would silently 404 every
  // private repository if we relied on automatic following.
  let response = await options.http.send({
    url,
    method: "GET",
    headers: {
      accept: "application/vnd.github+json",
      "user-agent": "RepoShield",
      ...(options.token ? { authorization: `Bearer ${options.token}` } : {}),
    },
    responseType: "bytes",
    followRedirects: false,
    maxBytes: MAX_ARCHIVE_BYTES,
  });

  if (response.status >= 300 && response.status < 400) {
    const location = response.headers?.location;
    if (!location) return null;
    response = await options.http.send({
      url: location,
      method: "GET",
      headers: { "user-agent": "RepoShield" },
      responseType: "bytes",
      maxBytes: MAX_ARCHIVE_BYTES,
    });
  }

  // Only call it a rate limit when GitHub says so. A 403 also covers SAML
  // enforcement, blocked repositories and abuse detection — reporting those as
  // "you are out of quota" sends the developer off to wait an hour for
  // something that will never resolve on its own.
  const remaining = response.headers?.["x-ratelimit-remaining"];
  if ((response.status === 403 || response.status === 429) && remaining === "0") {
    throw new GitHubError(
      "RATE_LIMITED",
      "GitHub's rate limit is exhausted for this server.",
      resetDate(response.headers),
    );
  }

  if (response.status !== 200 || !response.bytes) return null;
  return archiveBytesToResult(response.bytes);
}

/**
 * Turn a gzipped repository tarball into the analyzer's inputs.
 *
 * Shared by every provider: GitHub, GitLab and Bitbucket all serve a gzip
 * tarball whose first path segment is a wrapper directory, which `extractTarGz`
 * already strips — so the same extraction works for all three.
 */
export function archiveBytesToResult(bytes: Uint8Array): ArchiveResult | null {
  if (bytes.length > MAX_ARCHIVE_BYTES) return null;

  let entries;
  try {
    entries = extractTarGz(bytes, { maxFileBytes: MAX_FILE_BYTES, filter: isAnalysable });
  } catch {
    // Malformed or unexpected archive shape: fall back rather than fail.
    return null;
  }

  const contents = new Map<string, string>();
  const tree: FileEntry[] = [];
  let textBytes = 0;

  for (const entry of entries) {
    tree.push({ path: entry.path, type: "blob", size: entry.content.length });
    if (textBytes + entry.content.length > MAX_TEXT_BYTES) continue;
    if (looksBinary(entry.content)) continue;
    textBytes += entry.content.length;
    contents.set(entry.path, utf8Decode(entry.content));
  }

  return { contents, tree, considered: tree.length, archiveBytes: bytes.length };
}

function resetDate(headers?: Record<string, string>): Date | undefined {
  const reset = headers?.["x-ratelimit-reset"];
  return reset ? new Date(Number(reset) * 1000) : undefined;
}
