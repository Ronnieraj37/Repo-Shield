/**
 * Deliberately lightweight config parsing.
 *
 * We are not trying to build correct TOML/YAML parsers — we are trying to
 * extract a handful of security-relevant keys from files that are frequently
 * malformed on purpose. Regex extraction degrades gracefully where a strict
 * parser would throw and take the whole scan with it. Anything ambiguous falls
 * through to the raw-text rules in `rules.ts`, which see every file anyway.
 */

export interface PackageJson {
  name?: string;
  scripts: Record<string, string>;
  dependencies: Record<string, string>;
  devDependencies: Record<string, string>;
  optionalDependencies: Record<string, string>;
  overrides: Record<string, unknown>;
  resolutions: Record<string, unknown>;
  browser?: unknown;
  raw: Record<string, unknown>;
}

export interface VscodeTask {
  label?: string;
  command?: string;
  args?: string[];
  type?: string;
  runsOnFolderOpen: boolean;
}

/** Strip `//` and block comments so JSON-with-comments files parse. */
export function parseJsonc<T = unknown>(text: string): T | null {
  try {
    return JSON.parse(text) as T;
  } catch {
    // fall through to the tolerant path
  }
  const stripped = text
    .replace(/\\"|"(?:\\"|[^"])*"|(\/\/.*$)/gm, (match, comment) =>
      comment ? "" : match,
    )
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/,(\s*[}\]])/g, "$1");
  try {
    return JSON.parse(stripped) as T;
  } catch {
    return null;
  }
}

export function parsePackageJson(text: string): PackageJson | null {
  const raw = parseJsonc<Record<string, unknown>>(text);
  if (!raw || typeof raw !== "object") return null;

  const asRecord = (value: unknown): Record<string, string> =>
    value && typeof value === "object" && !Array.isArray(value)
      ? Object.fromEntries(
          Object.entries(value as Record<string, unknown>).map(([k, v]) => [
            k,
            String(v),
          ]),
        )
      : {};

  return {
    name: typeof raw.name === "string" ? raw.name : undefined,
    scripts: asRecord(raw.scripts),
    dependencies: asRecord(raw.dependencies),
    devDependencies: asRecord(raw.devDependencies),
    optionalDependencies: asRecord(raw.optionalDependencies),
    overrides:
      (raw.overrides as Record<string, unknown> | undefined) ?? {},
    resolutions:
      (raw.resolutions as Record<string, unknown> | undefined) ?? {},
    browser: raw.browser,
    raw,
  };
}

/**
 * Extract tasks from `.vscode/tasks.json`, including whether they auto-run.
 *
 * `runOptions.runOn: "folderOpen"` is the part that matters: a task with that
 * set executes the moment the developer opens the folder in VS Code, with no
 * prompt and no `npm install` required. Merely having a `command` is normal.
 */
export function parseVscodeTasks(text: string): VscodeTask[] {
  const parsed = parseJsonc<{ tasks?: unknown[] }>(text);
  const tasks = Array.isArray(parsed?.tasks) ? parsed.tasks : [];
  return tasks
    .filter((t): t is Record<string, unknown> => !!t && typeof t === "object")
    .map((t) => {
      const runOptions = t.runOptions as { runOn?: string } | undefined;
      return {
        label: typeof t.label === "string" ? t.label : undefined,
        command: typeof t.command === "string" ? t.command : undefined,
        args: Array.isArray(t.args) ? t.args.map(String) : undefined,
        type: typeof t.type === "string" ? t.type : undefined,
        runsOnFolderOpen: runOptions?.runOn === "folderOpen",
      };
    });
}

/** Read a top-level `key = value` out of a TOML file, ignoring comments. */
export function tomlValue(text: string, key: string): string | null {
  const pattern = new RegExp(`^\\s*${key}\\s*=\\s*(.+?)\\s*(?:#.*)?$`, "m");
  const match = text.match(pattern);
  if (!match) return null;
  return match[1].replace(/^["']|["']$/g, "");
}

/** Whether a TOML file contains a given `[section]` header. */
export function tomlHasSection(text: string, section: string): boolean {
  return new RegExp(`^\\s*\\[${section.replace(/\./g, "\\.")}\\]`, "m").test(
    text,
  );
}

/** Read a top-level `key: value` out of a YAML file. */
export function yamlValue(text: string, key: string): string | null {
  const match = text.match(new RegExp(`^${key}\\s*:\\s*(.+?)\\s*(?:#.*)?$`, "m"));
  if (!match) return null;
  return match[1].replace(/^["']|["']$/g, "");
}

export interface WorkflowInfo {
  triggers: string[];
  /** `uses:` refs that aren't SHA-pinned. */
  unpinnedActions: { action: string; line: number }[];
}

export function parseWorkflow(text: string): WorkflowInfo {
  const triggers: string[] = [];
  const unpinnedActions: { action: string; line: number }[] = [];

  const onBlock = text.match(/^on:\s*([\s\S]*?)^\S/m)?.[1] ?? text;
  for (const trigger of [
    "pull_request_target",
    "pull_request",
    "push",
    "workflow_run",
    "issue_comment",
  ]) {
    if (new RegExp(`\\b${trigger}\\b\\s*:`).test(onBlock)) triggers.push(trigger);
  }

  text.split("\n").forEach((line, index) => {
    const uses = line.match(/^\s*(?:-\s*)?uses:\s*["']?([^"'\s]+)/);
    if (!uses) return;
    const ref = uses[1];
    if (ref.startsWith("./") || ref.startsWith("docker://")) return;
    const version = ref.split("@")[1];
    // A 40-char hex ref is a commit SHA; anything else is a movable tag that
    // the action's owner can repoint at new code after you've reviewed it.
    if (!version || !/^[0-9a-f]{40}$/i.test(version)) {
      unpinnedActions.push({ action: ref, line: index + 1 });
    }
  });

  return { triggers, unpinnedActions };
}

export interface NpmrcInfo {
  customRegistries: { key: string; value: string; line: number }[];
  hasAuthToken: boolean;
}

export function parseNpmrc(text: string): NpmrcInfo {
  const customRegistries: NpmrcInfo["customRegistries"] = [];
  let hasAuthToken = false;

  text.split("\n").forEach((line, index) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith(";")) return;
    const [key, ...rest] = trimmed.split("=");
    const value = rest.join("=").trim();
    if (/_authToken/i.test(key)) hasAuthToken = true;
    if (/registry/i.test(key) && value) {
      const isOfficial = /^https:\/\/registry\.(npmjs\.org|yarnpkg\.com)\/?$/.test(
        value,
      );
      if (!isOfficial) {
        customRegistries.push({ key: key.trim(), value, line: index + 1 });
      }
    }
  });

  return { customRegistries, hasAuthToken };
}
