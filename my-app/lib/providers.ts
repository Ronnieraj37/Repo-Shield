import type { HttpClient } from "./analyzer/http";
import type { FileEntry, RepoMeta } from "./analyzer/types";
import {
  archiveBytesToResult,
  isAnalysable,
  MAX_FILE_BYTES,
  MAX_TEXT_BYTES,
} from "./github-archive";
import { looksBinary, utf8Decode } from "./analyzer/portable";
import { GitHubError } from "./github";

/**
 * Public-repo support for GitLab and Bitbucket.
 *
 * The analyzer is source-agnostic — it takes a file tree and contents — so
 * adding a host is just a fetch adapter. Both GitLab and Bitbucket serve a
 * gzip tarball of a public repo with no auth, exactly like GitHub, and the
 * shared `archiveBytesToResult` handles the extraction. Private repos on these
 * hosts are out of scope (they'd need each provider's own OAuth flow).
 */

export type RepoHost = "github" | "gitlab" | "bitbucket";

const MAX_ARCHIVE_BYTES = 90 * 1024 * 1024;

export interface ProviderResult {
  repo: RepoMeta;
  tree: FileEntry[];
  contents: Map<string, string>;
  considered: number;
  archiveBytes: number;
}

/** Which host a parsed repo belongs to, from its URL. */
export function detectHost(raw: string): RepoHost {
  const s = raw.toLowerCase();
  if (s.includes("gitlab.com") || s.includes("gitlab.org")) return "gitlab";
  if (s.includes("bitbucket.org")) return "bitbucket";
  return "github";
}

async function getJson<T>(http: HttpClient, url: string): Promise<T | null> {
  const res = await http.send({ url, method: "GET", headers: { "user-agent": "RepoShield", accept: "application/json" } });
  if (res.status === 404) return null;
  if (res.status !== 200) {
    throw new GitHubError(
      res.status === 403 || res.status === 429 ? "RATE_LIMITED" : "NETWORK",
      `The provider returned ${res.status}.`,
    );
  }
  try {
    return JSON.parse(res.body) as T;
  } catch {
    return null;
  }
}

async function getArchive(
  http: HttpClient,
  url: string,
): Promise<Uint8Array | null> {
  // Both hosts redirect the archive to a CDN; follow it manually so no auth
  // header rides along to a third-party origin (matches the GitHub path).
  let res = await http.send({
    url,
    method: "GET",
    headers: { "user-agent": "RepoShield" },
    responseType: "bytes",
    followRedirects: false,
    maxBytes: MAX_ARCHIVE_BYTES,
  });
  if (res.status >= 300 && res.status < 400 && res.headers?.location) {
    res = await http.send({
      url: res.headers.location,
      method: "GET",
      headers: { "user-agent": "RepoShield" },
      responseType: "bytes",
      maxBytes: MAX_ARCHIVE_BYTES,
    });
  }
  return res.status === 200 && res.bytes ? res.bytes : null;
}

/**
 * Fetch and extract a public GitLab or Bitbucket repository.
 * Returns null for GitHub (handled elsewhere) or if the repo can't be read.
 */
export async function fetchPublicRepo(
  host: RepoHost,
  owner: string,
  name: string,
  ref: string | undefined,
  http: HttpClient,
): Promise<ProviderResult | null> {
  if (host === "gitlab") return fetchGitlab(owner, name, ref, http);
  if (host === "bitbucket") return fetchBitbucket(owner, name, ref, http);
  return null;
}

/**
 * GitLab's repository archive endpoint sits behind bot protection that rejects
 * a server-side `fetch` (undici's TLS fingerprint) with 406, regardless of
 * headers — so the one-request tarball path GitHub and Bitbucket use isn't open
 * to us here. GitLab's JSON REST API, however, answers normally: we list the
 * tree in one paginated sweep and pull the raw bytes of each analysable file.
 *
 * That costs one request per file, so we cap how many we fetch. The repos this
 * tool exists to catch — fake take-home projects from a fake recruiter — are
 * small, tens of files, well inside the cap and GitLab's 500/min anonymous
 * limit. A genuinely large repo is truncated to the cap rather than failing;
 * the malicious payload lives in the manifest and install hooks, which sort to
 * the front, so truncation costs nothing that matters.
 */
const GITLAB_MAX_FILES = 400;
const GITLAB_CONCURRENCY = 8;

interface GitlabTreeItem {
  path: string;
  type: "blob" | "tree";
}

async function fetchGitlab(
  owner: string,
  name: string,
  ref: string | undefined,
  http: HttpClient,
): Promise<ProviderResult | null> {
  const projectPath = encodeURIComponent(`${owner}/${name}`);
  const api = `https://gitlab.com/api/v4/projects/${projectPath}`;
  const meta = await getJson<{ default_branch: string; web_url: string; star_count?: number; last_activity_at?: string }>(
    http,
    api,
  );
  if (!meta) throw new GitHubError("NOT_FOUND", "That GitLab repository does not exist, or it is private.");

  const branch = ref ?? meta.default_branch;

  // Walk the whole tree (keyset pagination) so `tree` reflects the real repo,
  // then keep only the blobs worth decoding.
  const tree: FileEntry[] = [];
  const wanted: string[] = [];
  let pageUrl: string | null =
    `${api}/repository/tree?recursive=true&per_page=100&pagination=keyset&ref=${encodeURIComponent(branch)}`;
  for (let guard = 0; pageUrl && guard < 200; guard++) {
    const page: { items: GitlabTreeItem[] | null; next: string | null } =
      await getJsonPaged<GitlabTreeItem[]>(http, pageUrl);
    if (!page.items) break;
    for (const item of page.items) {
      if (item.type !== "blob") continue;
      tree.push({ path: item.path, type: "blob" });
      if (isAnalysable(item.path) && wanted.length < GITLAB_MAX_FILES) {
        wanted.push(item.path);
      }
    }
    pageUrl = page.next;
  }
  if (tree.length === 0) return null;

  const contents = new Map<string, string>();
  let textBytes = 0;
  let index = 0;
  async function worker() {
    while (index < wanted.length && textBytes < MAX_TEXT_BYTES) {
      const path = wanted[index++];
      const raw = await getRaw(
        http,
        `${api}/repository/files/${encodeURIComponent(path)}/raw?ref=${encodeURIComponent(branch)}`,
      );
      if (!raw || raw.length > MAX_FILE_BYTES || looksBinary(raw)) continue;
      if (textBytes + raw.length > MAX_TEXT_BYTES) continue;
      textBytes += raw.length;
      contents.set(path, utf8Decode(raw));
    }
  }
  await Promise.all(
    Array.from({ length: Math.min(GITLAB_CONCURRENCY, wanted.length) }, worker),
  );

  return {
    repo: {
      owner, name, host: "gitlab",
      url: meta.web_url ?? `https://gitlab.com/${owner}/${name}`,
      ref: branch, commit: branch, isPrivate: false,
      stars: meta.star_count, pushedAt: meta.last_activity_at, defaultBranch: meta.default_branch,
    },
    tree,
    contents,
    considered: contents.size,
    archiveBytes: textBytes,
  };
}

/** A paginated GitLab JSON GET: returns the parsed body and the next-page URL. */
async function getJsonPaged<T>(
  http: HttpClient,
  url: string,
): Promise<{ items: T | null; next: string | null }> {
  const res = await http.send({
    url,
    method: "GET",
    headers: { "user-agent": "RepoShield", accept: "application/json" },
  });
  if (res.status !== 200) {
    if (res.status === 403 || res.status === 429) {
      throw new GitHubError("RATE_LIMITED", "GitLab's rate limit is exhausted for this server.");
    }
    return { items: null, next: null };
  }
  let items: T | null = null;
  try {
    items = JSON.parse(res.body) as T;
  } catch {
    return { items: null, next: null };
  }
  return { items, next: res.headers?.link ? nextFromLink(res.headers.link) : null };
}

/** Pull the `rel="next"` URL out of an RFC 5988 Link header, if present. */
function nextFromLink(link: string): string | null {
  const match = link.split(",").find((part) => /rel="next"/.test(part));
  const url = match?.match(/<([^>]+)>/);
  return url ? url[1] : null;
}

/** Fetch a raw file as bytes. Returns null on any non-200. */
async function getRaw(http: HttpClient, url: string): Promise<Uint8Array | null> {
  const res = await http.send({
    url,
    method: "GET",
    headers: { "user-agent": "RepoShield" },
    responseType: "bytes",
    maxBytes: MAX_FILE_BYTES,
  });
  return res.status === 200 && res.bytes ? res.bytes : null;
}

async function fetchBitbucket(
  owner: string,
  name: string,
  ref: string | undefined,
  http: HttpClient,
): Promise<ProviderResult | null> {
  const meta = await getJson<{ mainbranch?: { name: string }; full_name?: string; is_private?: boolean }>(
    http,
    `https://api.bitbucket.org/2.0/repositories/${owner}/${name}`,
  );
  if (!meta?.full_name) throw new GitHubError("NOT_FOUND", "That Bitbucket repository does not exist, or it is private.");

  const branch = ref ?? meta.mainbranch?.name ?? "main";
  const bytes = await getArchive(
    http,
    `https://bitbucket.org/${owner}/${name}/get/${encodeURIComponent(branch)}.tar.gz`,
  );
  if (!bytes) return null;

  const extracted = archiveBytesToResult(bytes);
  if (!extracted) return null;

  return {
    repo: {
      owner, name, host: "bitbucket",
      url: `https://bitbucket.org/${owner}/${name}`,
      ref: branch, commit: branch, isPrivate: false,
      defaultBranch: meta.mainbranch?.name,
    },
    ...extracted,
  };
}
