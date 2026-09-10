import type { FileEntry } from "./types";

/**
 * What a file is, and what it could do to you.
 *
 * Every rule in `rules.ts` used to run against every file, which produced
 * confident nonsense: `deriveKey(string mnemonic, uint32 index)` in
 * forge-std's `Vm.sol` reported as "code targets cryptocurrency wallet
 * storage", and OpenZeppelin's EIP-712 doc comment reported the same because
 * it links to MetaMask's documentation.
 *
 * Two facts fix most of that.
 *
 * **Solidity cannot touch your machine.** It compiles to EVM bytecode and runs
 * in a sandbox with no filesystem, no network and no shell. A `.sol` file
 * cannot read `~/.ssh`, cannot POST anywhere, and cannot spawn a process. The
 * single exception is Foundry's `vm.ffi()` cheatcode, which needs
 * `ffi = true` — and that has its own rule. Applying host-threat rules to
 * Solidity is a category error.
 *
 * **Most files in a repository were not written by its author.** In the repo
 * that prompted this, 871 of 961 files were vendored dependencies —
 * forge-std and OpenZeppelin, checked in under `lib/`. Reporting their
 * contents as the author's intent is both wrong and, at 18 findings, louder
 * than anything the author actually wrote.
 */

/** Where a file's code can actually execute. */
export type ExecContext =
  /** Runs on the developer's machine, with their privileges. */
  | "host"
  /** Runs in the EVM sandbox. No filesystem, no network, no shell. */
  | "evm"
  /** Not executed at all — documentation, fixtures, data. */
  | "inert";

export interface FileClass {
  context: ExecContext;
  /** Third-party code the repo author did not write. */
  vendored: boolean;
  /** Tests, fixtures and mocks, which legitimately contain alarming data. */
  test: boolean;
  /** Build output, lockfiles, minified bundles. */
  generated: boolean;
  /**
   * Named by something that executes it — an install hook, an editor task, a
   * CI step. Such a file is the author's choice wherever it lives, so it is
   * never softened for being vendored.
   */
  referenced: boolean;
}

/** Languages and configs that can run commands on your machine. */
const HOST_EXECUTABLE =
  /\.(js|cjs|mjs|jsx|ts|tsx|mts|cts|py|rb|go|rs|php|pl|lua|sh|bash|zsh|fish|ps1|bat|cmd|nu)$/i;

/** Sandboxed chain languages. These cannot reach the host. */
const CHAIN_LANGUAGE = /\.(sol|vy|cairo|move|fe|huff|yul)$/i;

/**
 * Data files that nonetheless drive host execution: a manifest's install
 * hooks, an editor task, a CI job. Treated as `host` because running them is
 * exactly what happens to you.
 */
const HOST_CONFIG =
  /(^|\/)(package\.json|\.npmrc|\.yarnrc\.ya?ml|\.pnpmfile\.cjs|Makefile|justfile|Justfile|Dockerfile[^/]*|docker-compose[^/]*\.ya?ml|Procfile|Taskfile\.ya?ml|\.travis\.yml|foundry\.toml|Cargo\.toml|pyproject\.toml|setup\.py|conftest\.py|sitecustomize\.py|build\.rs|go\.mod)$|(^|\/)\.vscode\/|(^|\/)\.devcontainer\/|(^|\/)\.idea\/|(^|\/)\.github\/workflows\/|(^|\/)\.circleci\/|(^|\/)\.gitlab-ci\.yml$/;

/** Directory names that always hold someone else's code. */
const DEPENDENCY_DIR =
  /(^|\/)(node_modules|bower_components|vendor|third_party|thirdparty|external|Godeps|\.yarn\/(cache|unplugged)|site-packages|\.venv|venv|\.cargo|\.pnpm)\//;

const TEST_PATH =
  /(^|\/)_?(tests?|__tests__|__mocks__|specs?|fixtures?|mocks?|testdata|e2e|cypress|\.storybook)\//i;
const TEST_FILE = /\.(t|test|spec)\.[a-z]+$|_test\.[a-z]+$|(^|\/)test_[^/]+$/i;

/**
 * Compiled output. Not written by anyone, and frequently a duplicate of source
 * that has already been analysed — ethers.js ships its whole test suite
 * compiled into `lib.commonjs/`, which doubled every finding.
 */
const GENERATED_PATH =
  /(^|\/)(dist|build|out|coverage|artifacts|cache|\.next|__pycache__|target|lib\.(commonjs|esm|cjs)|esm|cjs|umd|es5|types)\//;
const GENERATED_FILE =
  /\.min\.(js|css)$|\.map$|(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|Cargo\.lock|poetry\.lock|Pipfile\.lock|go\.sum|composer\.lock|Gemfile\.lock)$/;

/**
 * Work out which directories hold dependencies rather than the author's code.
 *
 * Three sources, because no single one is sufficient:
 *
 *   - `.gitmodules` names submodule paths outright. Authoritative when present.
 *   - Foundry installs dependencies into `lib/` beside `foundry.toml`. That is
 *     a convention, not a name we can hardcode — a `lib/` directory elsewhere
 *     is usually the author's own source, so it is only treated as vendored
 *     next to a Foundry manifest.
 *   - The universal dependency directory names, at any depth.
 *
 * Returns path prefixes; a file is vendored if it starts with any of them.
 */
export function findVendoredRoots(
  tree: FileEntry[],
  contents: Map<string, string>,
): string[] {
  const roots = new Set<string>();

  // Foundry: `lib/` is a sibling of foundry.toml, at any depth.
  for (const entry of tree) {
    if (!/(^|\/)foundry\.toml$/.test(entry.path)) continue;
    const dir = entry.path.includes("/")
      ? entry.path.slice(0, entry.path.lastIndexOf("/") + 1)
      : "";
    roots.add(`${dir}lib/`);
  }

  // Submodules, wherever the .gitmodules file happens to live.
  for (const [path, text] of contents) {
    if (!/(^|\/)\.gitmodules$/.test(path)) continue;
    const dir = path.includes("/") ? path.slice(0, path.lastIndexOf("/") + 1) : "";
    for (const match of text.matchAll(/^\s*path\s*=\s*(.+?)\s*$/gm)) {
      roots.add(`${dir}${match[1].replace(/\/$/, "")}/`);
    }
  }

  return [...roots];
}

export function classify(
  path: string,
  vendoredRoots: readonly string[],
): FileClass {
  const vendored =
    DEPENDENCY_DIR.test(path) ||
    vendoredRoots.some((root) => path.startsWith(root));

  const context: ExecContext = CHAIN_LANGUAGE.test(path)
    ? "evm"
    : HOST_CONFIG.test(path) || HOST_EXECUTABLE.test(path)
      ? "host"
      : "inert";

  return {
    context,
    vendored,
    test: TEST_PATH.test(path) || TEST_FILE.test(path),
    generated: GENERATED_PATH.test(path) || GENERATED_FILE.test(path),
    referenced: false,
  };
}

/** Classify a whole repository once, so rules can look files up cheaply. */
export function classifyAll(
  tree: FileEntry[],
  contents: Map<string, string>,
): Map<string, FileClass> {
  const roots = findVendoredRoots(tree, contents);
  const out = new Map<string, FileClass>();
  for (const entry of tree) {
    if (entry.type !== "blob") continue;
    out.set(entry.path, classify(entry.path, roots));
  }
  // Contents can include files the tree missed (referenced-file fetches).
  for (const path of contents.keys()) {
    if (!out.has(path)) out.set(path, classify(path, roots));
  }
  return out;
}
