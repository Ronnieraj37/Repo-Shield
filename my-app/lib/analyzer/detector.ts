import type { FileEntry, FrameworkType, ProjectProfile } from "./types";

/**
 * Framework fingerprints. Order matters only for display; a repo can match
 * several (a Hardhat project with a Cargo-based zk circuit, say).
 */
const FRAMEWORK_FINGERPRINTS: { framework: FrameworkType; test: RegExp }[] = [
  { framework: "foundry", test: /^foundry\.toml$/ },
  { framework: "hardhat", test: /^hardhat\.config\.(js|ts|cjs|mjs)$/ },
  { framework: "truffle", test: /^truffle-config\.js$/ },
  { framework: "anchor", test: /^Anchor\.toml$/ },
  { framework: "cargo", test: /^Cargo\.toml$/ },
  { framework: "go", test: /^go\.mod$/ },
  { framework: "deno", test: /^deno\.jsonc?$/ },
  { framework: "bun", test: /^bun\.lock(b)?$/ },
  { framework: "python", test: /^(pyproject\.toml|requirements\.txt|setup\.py|Pipfile)$/ },
  { framework: "nodejs", test: /^package\.json$/ },
];

const LANGUAGE_BY_EXTENSION: Record<string, string> = {
  ts: "TypeScript",
  tsx: "TypeScript",
  js: "JavaScript",
  jsx: "JavaScript",
  mjs: "JavaScript",
  cjs: "JavaScript",
  sol: "Solidity",
  rs: "Rust",
  go: "Go",
  py: "Python",
  sh: "Shell",
  bash: "Shell",
  ps1: "PowerShell",
  rb: "Ruby",
  java: "Java",
  vy: "Vyper",
  move: "Move",
  cairo: "Cairo",
};

const LOCKFILES = new Set([
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "bun.lockb",
  "bun.lock",
  "Cargo.lock",
  "poetry.lock",
  "Pipfile.lock",
  "go.sum",
]);

const PACKAGE_MANAGER_BY_LOCKFILE: Record<string, string> = {
  "package-lock.json": "npm",
  "yarn.lock": "yarn",
  "pnpm-lock.yaml": "pnpm",
  "bun.lockb": "bun",
  "bun.lock": "bun",
  "Cargo.lock": "cargo",
  "poetry.lock": "poetry",
  "Pipfile.lock": "pipenv",
  "go.sum": "go modules",
};

/**
 * Files that get fetched no matter what the project turns out to be, because
 * they are dangerous by nature rather than by framework. Each carries a
 * priority — when the byte budget runs out, low numbers survive.
 */
const ALWAYS_FETCH: { test: RegExp; priority: number }[] = [
  // Auto-executing editor config. This is the Lazarus signature move.
  { test: /^\.vscode\/(tasks|launch|settings)\.json$/, priority: 0 },
  { test: /^\.devcontainer\/.*\.(json|jsonc)$/, priority: 0 },
  { test: /^\.idea\/.*\.xml$/, priority: 2 },

  // Package manager config that can redirect where code comes from.
  { test: /^\.npmrc$/, priority: 0 },
  { test: /^\.yarnrc\.ya?ml$/, priority: 0 },
  { test: /^\.yarn\/plugins\/.+/, priority: 0 },
  { test: /^\.pnpmfile\.cjs$/, priority: 0 },

  // Manifests and build scripts that execute on install/build.
  { test: /^package\.json$/, priority: 0 },
  { test: /^(setup\.py|conftest\.py|sitecustomize\.py)$/, priority: 0 },
  { test: /^build\.rs$/, priority: 0 },
  { test: /^(Cargo|foundry|Anchor|pyproject)\.toml$/, priority: 1 },
  { test: /^hardhat\.config\.(js|ts|cjs|mjs)$/, priority: 1 },
  { test: /^truffle-config\.js$/, priority: 1 },
  { test: /^go\.mod$/, priority: 1 },
  { test: /^deno\.jsonc?$/, priority: 1 },

  // Root-level scripts a "setup instructions" README will tell you to run.
  { test: /^[^/]+\.(sh|bash|zsh|bat|cmd|ps1)$/, priority: 1 },
  { test: /^(Makefile|justfile|Justfile|Taskfile\.ya?ml)$/, priority: 1 },
  { test: /^scripts\/[^/]+\.(sh|bash|js|cjs|mjs|py)$/, priority: 2 },

  // Container and CI definitions.
  { test: /^Dockerfile(\..+)?$/, priority: 2 },
  { test: /^docker-compose(\..+)?\.ya?ml$/, priority: 2 },
  { test: /^\.github\/workflows\/.+\.ya?ml$/, priority: 2 },

  // Build tooling that has been abused to hide execution.
  { test: /^(postcss|next|vite|webpack|rollup|tailwind|babel)\.config\.(js|ts|cjs|mjs)$/, priority: 2 },
  { test: /^\.eslintrc\.(js|cjs)$/, priority: 2 },

  // SVGs, because "it's just an image" is how JS gets smuggled in.
  { test: /\.svg$/, priority: 3 },
];

/** Directories whose contents are noise, not signal. */
const IGNORED_DIRS =
  /^(node_modules|vendor|target|\.git|dist|build|out|coverage|artifacts|cache)\//;

/**
 * Below this many files, read the whole repository rather than a selection.
 * A fake interview assignment is this size; a monorepo is not.
 */
const SMALL_REPO_FILES = 45;

/** Source and script files, for the small-repo sweep. */
const SOURCE_FILE =
  /\.(js|cjs|mjs|jsx|ts|tsx|py|rb|go|rs|sol|sh|bash|ps1|bat|cmd|json|ya?ml|toml|env|md)$/i;

/** Lockfiles are worth fetching but are huge; cap which ones we pull. */
const LOCKFILE_FETCH_LIMIT = 512 * 1024;

export function detectProject(tree: FileEntry[]): ProjectProfile {
  const blobs = tree.filter((e) => e.type === "blob");
  const paths = new Set(blobs.map((e) => e.path));

  const frameworks: FrameworkType[] = [];
  for (const { framework, test } of FRAMEWORK_FINGERPRINTS) {
    if (blobs.some((e) => test.test(e.path))) frameworks.push(framework);
  }
  // package.json alone means Node; alongside Hardhat it's redundant noise.
  const meaningful = frameworks.filter((f) => f !== "nodejs");
  const resolved =
    meaningful.length > 0 && frameworks.includes("nodejs")
      ? frameworks
      : frameworks.length > 0
        ? frameworks
        : (["unknown"] as FrameworkType[]);

  const languageCounts = new Map<string, number>();
  for (const entry of blobs) {
    if (IGNORED_DIRS.test(entry.path)) continue;
    const ext = entry.path.split(".").pop()?.toLowerCase();
    const language = ext ? LANGUAGE_BY_EXTENSION[ext] : undefined;
    if (language) {
      languageCounts.set(language, (languageCounts.get(language) ?? 0) + 1);
    }
  }
  const languages = [...languageCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([language]) => language);

  const packageManagers = [...LOCKFILES]
    .filter((f) => paths.has(f))
    .map((f) => PACKAGE_MANAGER_BY_LOCKFILE[f]);

  return {
    frameworks: resolved,
    languages,
    packageManagers,
    filesOfInterest: selectFilesToFetch(tree).map((e) => e.path),
    hasLockfile: [...LOCKFILES].some((f) => paths.has(f)),
    fileCount: blobs.length,
  };
}

export interface SelectionResult {
  /** What to fetch, best first. */
  selected: FileEntry[];
  /** Every blob that was a candidate, ignoring vendored/build directories. */
  considered: number;
  /** selected / considered, 0-1. Reported to the user, never hidden. */
  coverage: number;
}

export interface SelectionBudget {
  maxFiles?: number;
  maxBytes?: number;
}

/**
 * Decide which files are worth pulling over the wire.
 *
 * This is the part of the design that has to survive contact with a real
 * repository. A file tree arrives in one API call no matter how large it is,
 * but every file body is another call against a shared rate limit, so this can
 * never be "read everything" in the general case.
 *
 * Three regimes:
 *
 *   Small repo (the actual threat)  — a fake interview assignment is a few
 *     dozen files. Read all of them; the payload is as likely to be in
 *     `src/utils/analytics.js` as in a manifest.
 *
 *   Medium repo — read every file that executes automatically, plus whatever
 *     the risk score says is worth the call.
 *
 *   Huge monorepo — read the auto-executing files and the anomalies, and be
 *     honest in the report that coverage is a fraction of a percent. A verdict
 *     of "safe" over 0.2% of a repository is not a verdict, and the UI says so
 *     rather than quietly implying otherwise.
 */
export function selectFilesToFetch(
  tree: FileEntry[],
  budget: SelectionBudget = {},
): FileEntry[] {
  return selectFilesWithCoverage(tree, budget).selected;
}

export function selectFilesWithCoverage(
  tree: FileEntry[],
  budget: SelectionBudget = {},
): SelectionResult {
  const blobs = tree.filter(
    (e) => e.type === "blob" && !IGNORED_DIRS.test(e.path),
  );

  const readEverything = blobs.length <= SMALL_REPO_FILES;

  // Bigger repositories earn a bigger budget, but the ceiling is fixed —
  // otherwise a monorepo scan costs hundreds of API calls and minutes.
  const maxFiles =
    budget.maxFiles ?? (readEverything ? SMALL_REPO_FILES : blobs.length > 800 ? 110 : 70);
  const maxBytes = budget.maxBytes ?? 2_000_000;

  const scored: { entry: FileEntry; score: number }[] = [];
  for (const entry of blobs) {
    const score = scoreCandidate(entry, readEverything);
    if (score > 0) scored.push({ entry, score });
  }

  scored.sort((a, b) => {
    if (a.score !== b.score) return b.score - a.score;
    // Shallower paths first — root config is likelier to be the trap.
    const depth = a.entry.path.split("/").length - b.entry.path.split("/").length;
    if (depth !== 0) return depth;
    return a.entry.path.localeCompare(b.entry.path);
  });

  const selected: FileEntry[] = [];
  let bytes = 0;
  for (const { entry } of scored) {
    if (selected.length >= maxFiles) break;
    const size = entry.size ?? 4096;
    if (bytes + size > maxBytes) continue;
    bytes += size;
    selected.push(entry);
  }

  return {
    selected,
    considered: blobs.length,
    coverage: blobs.length === 0 ? 1 : selected.length / blobs.length,
  };
}

/** Higher means more worth spending an API call on. Zero means skip. */
function scoreCandidate(entry: FileEntry, readEverything: boolean): number {
  const path = entry.path;
  const size = entry.size ?? 0;

  const always = ALWAYS_FETCH.find((rule) => rule.test.test(path));
  // ALWAYS_FETCH priorities run 0 (most dangerous) to 3.
  if (always) return 100 - always.priority * 5;

  let score = 0;

  if (LOCKFILES.has(path) && size < LOCKFILE_FETCH_LIMIT) score += 70;
  else if (readEverything && SOURCE_FILE.test(path)) score += 40;
  else if (SOURCE_FILE.test(path)) score += 8;
  else return 0;

  // Anomalies worth a call even in a repository too large to read.
  //
  // A source file that is hundreds of kilobytes is either generated, vendored,
  // or hiding something — all three are worth a look.
  if (/\.(js|cjs|mjs|ts)$/.test(path) && size > 150_000) score += 45;
  // Hidden directories outside the known-config set.
  if (/(^|\/)\.[^/]+\//.test(path)) score += 25;
  // Names that suggest something was left behind rather than written.
  if (/(^|\/)(tmp|temp|backup|old|copy|new|test2|final)[^/]*$/i.test(path)) score += 15;
  // Double extensions: `logo.svg.js`, `readme.md.sh`.
  if (/\.[a-z0-9]{2,4}\.[a-z0-9]{1,4}$/i.test(path)) score += 30;
  // Shallow files are likelier to be the entry point a README tells you to run.
  score += Math.max(0, 12 - path.split("/").length * 3);

  return score;
}

/** Committed native binaries — flagged by R25, never fetched. */
export function findBinaryArtifacts(tree: FileEntry[]): FileEntry[] {
  return tree.filter(
    (e) =>
      e.type === "blob" &&
      !IGNORED_DIRS.test(e.path) &&
      /\.(node|so|dylib|dll|exe|bin|wasm)$/i.test(e.path),
  );
}

/**
 * Files that the already-fetched configs point at.
 *
 * The trap is almost never in the file that trips the rule. `.vscode/tasks.json`
 * is three lines and obviously suspicious; the payload lives in the script it
 * names. A `postinstall` hook is one line; the damage is in `scripts/setup.js`.
 * Fetching only the config files means reporting "this auto-runs something"
 * without ever reading the something.
 *
 * So after the first round, the fetched configs are scanned for paths that
 * exist in the tree, and those get pulled too.
 */
export function findReferencedFiles(
  contents: Map<string, string>,
  tree: FileEntry[],
  alreadyFetched: Set<string>,
  limit = 15,
): string[] {
  const inTree = new Map(
    tree.filter((e) => e.type === "blob").map((e) => [e.path, e]),
  );
  const found = new Set<string>();

  // Quoted or bare paths ending in an extension worth reading. Deliberately
  // permissive about the surrounding syntax — this runs over JSON, YAML, TOML,
  // Makefiles and shell alike.
  // The leading dot is part of the path, not a prefix to strip: `.vscode` is
  // a directory name. Only an explicit `./` or `../` is a prefix.
  const reference =
    /(?:^|[\s"'`(=,:])((?:\.{1,2}\/)?(?:[\w.-]+\/)*[\w.-]+\.(?:js|cjs|mjs|ts|py|sh|bash|ps1|rb|rs|go|json))(?=$|[\s"'`),;:])/gm;

  for (const [file, content] of contents) {
    // Only follow references out of files that can cause execution. Following
    // them out of a lockfile would pull in half the repository.
    if (!/^(package\.json|\.vscode\/|\.devcontainer\/|Makefile|justfile|Dockerfile|docker-compose|\.github\/workflows\/|.*\.(sh|bash|toml|yml|yaml)$)/.test(file)) {
      continue;
    }

    for (const match of content.matchAll(reference)) {
      const candidate = match[1].replace(/^\.\//, "");
      if (found.size >= limit) break;
      if (alreadyFetched.has(candidate) || found.has(candidate)) continue;
      if (IGNORED_DIRS.test(candidate)) continue;

      // Resolve against the referencing file's directory as well as the root,
      // since `.vscode/tasks.json` says "prepare.js" meaning ".vscode/prepare.js".
      const dir = file.includes("/") ? `${file.slice(0, file.lastIndexOf("/"))}/` : "";
      const resolved = inTree.has(candidate)
        ? candidate
        : inTree.has(dir + candidate)
          ? dir + candidate
          : null;

      if (resolved && !alreadyFetched.has(resolved)) found.add(resolved);
    }
  }

  return [...found];
}
