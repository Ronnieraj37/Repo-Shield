import type { FileEntry, Finding, Severity } from "./types";
import {
  parseNpmrc,
  parsePackageJson,
  parseVscodeTasks,
  parseWorkflow,
  tomlHasSection,
  tomlValue,
  type PackageJson,
} from "./parser";
import { findBinaryArtifacts } from "./detector";

export interface RuleContext {
  tree: FileEntry[];
  files: Map<string, string>;
  paths: Set<string>;
  packageJson: PackageJson | null;
}

interface Hit {
  file: string;
  line?: number;
  evidence: string;
  /** Overrides the rule's default title when a rule reports several shapes. */
  title?: string;
  severity?: Severity;
  description?: string;
}

interface Rule {
  id: string;
  severity: Severity;
  category: string;
  title: string;
  description: string;
  recommendation: string;
  run(ctx: RuleContext): Hit[];
}

const MAX_EVIDENCE = 400;

function snip(text: string, max = MAX_EVIDENCE): string {
  const collapsed = text.replace(/\s+/g, " ").trim();
  return collapsed.length > max ? `${collapsed.slice(0, max)}…` : collapsed;
}

/** Every line of `content` matching `pattern`, as hits. */
function grep(file: string, content: string, pattern: RegExp): Hit[] {
  const hits: Hit[] = [];
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const flags = pattern.flags.replace(/[gy]/g, "");
    if (new RegExp(pattern.source, flags).test(lines[i])) {
      hits.push({ file, line: i + 1, evidence: snip(lines[i]) });
    }
  }
  return hits;
}

/** Run `pattern` across every text file, optionally restricted by path. */
function grepAll(
  ctx: RuleContext,
  pattern: RegExp,
  pathFilter?: RegExp,
  exclude?: RegExp,
): Hit[] {
  const hits: Hit[] = [];
  for (const [file, content] of ctx.files) {
    if (pathFilter && !pathFilter.test(file)) continue;
    if (exclude && exclude.test(file)) continue;
    hits.push(...grep(file, content, pattern));
  }
  return hits;
}

/** Prose files describe credential paths legitimately; code does not. */
const PROSE_FILES = /\.(md|mdx|txt|rst|adoc)$|^(LICENSE|CHANGELOG)/i;

const LIFECYCLE_SCRIPTS = [
  "preinstall",
  "install",
  "postinstall",
  "prepare",
  "prepublish",
  "prepack",
  "postpack",
];

/**
 * Not all install hooks are equally abused.
 *
 * Measured across malicious npm packages, ~72% exploit an install script, and
 * `preinstall` alone accounts for ~61% — it runs before any dependency is
 * even fetched, so it is the earliest possible foothold. `postinstall` is a
 * distant second at ~7% and is also where most *legitimate* native-module
 * builds live. Same pattern, different prior.
 *
 * Source: benchmark analysis of npm malicious-package corpora, 2026.
 */
const LIFECYCLE_PRIOR: Record<string, number> = {
  preinstall: 3,
  install: 2,
  prepare: 2,
  postinstall: 1,
  prepublish: 1,
  prepack: 1,
  postpack: 1,
};

/** Lifecycle script entries as `[name, body]`, or [] when there's no manifest. */
function lifecycleEntries(ctx: RuleContext): [string, string][] {
  if (!ctx.packageJson) return [];
  return Object.entries(ctx.packageJson.scripts).filter(([name]) =>
    LIFECYCLE_SCRIPTS.includes(name),
  );
}

const POPULAR_PACKAGES = [
  "react", "react-dom", "next", "express", "lodash", "axios", "chalk",
  "commander", "dotenv", "ethers", "web3", "viem", "wagmi", "hardhat",
  "typescript", "eslint", "prettier", "jest", "vitest", "mocha", "chai",
  "webpack", "vite", "rollup", "babel", "tailwindcss", "postcss", "zod",
  "socket.io", "mongoose", "prisma", "graphql", "apollo-client", "redux",
  "@openzeppelin/contracts", "bignumber.js", "bn.js", "cross-env", "colors",
  "debug", "uuid", "moment", "dayjs", "node-fetch", "request", "yargs",
];

/**
 * Real, widely used packages that sit one edit from a name in the list above.
 * Without these, `color` gets reported as a typosquat of `colors` on a large
 * share of real repositories.
 */
const KNOWN_GOOD = new Set([
  "color", "colorette", "picocolors", "ansi-colors", "kleur",
  "chai", "chalk-template", "reactive", "next-auth", "nextra",
  "expressive", "lodash-es", "axios-retry", "viem-abi", "prettier-plugin-solidity",
  "zod-to-json-schema", "vitest", "jest-environment-jsdom", "webpack-cli",
  "postcss-import", "tailwind-merge", "prisma-client", "graphql-tag",
]);

/**
 * Damerau-Levenshtein: edit distance that counts a swap of two adjacent
 * characters as one edit rather than two.
 *
 * That distinction is the whole rule. Transposition is the commonest
 * typosquat — `axois` for `axios`, `lodahs` for `lodash`, `chakl` for `chalk`.
 * Plain Levenshtein scores those as 2, which is also the distance between many
 * unrelated real packages, so a threshold loose enough to catch them is loose
 * enough to flag half of npm. Counting the swap as 1 separates them cleanly.
 */
function editDistance(a: string, b: string): number {
  if (Math.abs(a.length - b.length) > 3) return 99;

  // Three rows: the standard two, plus the one before for transpositions.
  let prev2: number[] = [];
  let prev: number[] = Array.from({ length: b.length + 1 }, (_, i) => i);

  for (let i = 1; i <= a.length; i++) {
    const curr: number[] = new Array(b.length + 1);
    curr[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(
        prev[j] + 1,      // deletion
        curr[j - 1] + 1,  // insertion
        prev[j - 1] + cost, // substitution
      );
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        curr[j] = Math.min(curr[j], prev2[j - 2] + 1); // transposition
      }
    }
    prev2 = prev;
    prev = curr;
  }
  return prev[b.length];
}

export const RULES: Rule[] = [
  {
    id: "R01",
    severity: "critical",
    category: "lifecycle-script",
    title: "Install script downloads and executes remote code",
    description:
      "A script that runs automatically during `npm install` pipes a remote file straight into a shell. Whatever is on that server at the moment you install is what runs on your machine.",
    recommendation:
      "Do not install. If you must inspect the repo, use `npm install --ignore-scripts` and read the URL's contents by hand first.",
    run: (ctx) =>
      lifecycleEntries(ctx)
        .filter(([, body]) =>
          /(curl|wget|iwr|Invoke-WebRequest)[^\n|]*\|\s*(ba)?sh|\|\s*node\b|\|\s*python3?\b/i.test(
            body,
          ),
        )
        .map(([name, body]) => ({
          file: "package.json",
          evidence: snip(`"${name}": "${body}" (runs automatically on install)`),
          description:
            LIFECYCLE_PRIOR[name] >= 3
              ? "A `preinstall` script that pipes a remote file into a shell. This runs before any dependency is fetched — it is the earliest foothold an attacker can take, and the single most abused hook in npm malware."
              : undefined,
        })),
  },
  {
    id: "R02",
    severity: "critical",
    category: "lifecycle-script",
    title: "Install script executes an encoded payload",
    description:
      "An install-time script hands an encoded blob to `node -e`, `eval`, or a decoder. Encoding here has one purpose: to stop you reading what it does.",
    recommendation:
      "Treat as malicious until proven otherwise. Decode the payload in a throwaway container before going anywhere near `npm install`.",
    run: (ctx) =>
      lifecycleEntries(ctx)
        .filter(([, body]) =>
          /(node|python3?|deno)\s+-e|eval|base64\s+-d|atob\(|Buffer\.from\([^)]*base64|fromCharCode/i.test(
            body,
          ),
        )
        .map(([name, body]) => ({
          file: "package.json",
          evidence: snip(`"${name}": "${body}"`),
        })),
  },
  {
    id: "R03",
    severity: "critical",
    category: "obfuscation",
    title: "Dynamic code execution in a config file",
    description:
      "`eval()` or `new Function()` in a configuration file builds code at runtime from a string. Config files are read by your tooling automatically, so this executes without you running anything.",
    recommendation:
      "Read the surrounding code to find where the string comes from. A remote or encoded source means this is a loader for something you cannot see.",
    run: (ctx) =>
      grepAll(
        ctx,
        /\beval\s*\(|new\s+Function\s*\(|vm\.runIn\w*Context/,
        /(config|rc)\.(js|ts|cjs|mjs)$|^\.\w+rc\.(js|cjs)$|\.json$|\.ya?ml$/,
      ),
  },
  {
    id: "R04",
    severity: "critical",
    category: "code-execution",
    title: "Shell spawning from a config or asset file",
    description:
      "`child_process` lets code run arbitrary shell commands. In a build config, an SVG, or a test fixture there is no legitimate reason for it.",
    recommendation:
      "Trace what command it builds and where the arguments come from. Do not open this project in an editor that auto-runs build tooling until you have.",
    run: (ctx) =>
      grepAll(
        ctx,
        /require\(['"]child_process['"]\)|from\s+['"]child_process['"]|execSync|spawnSync|\.exec\s*\(/,
        /(config|rc)\.(js|ts|cjs|mjs)$|\.svg$|\.json$/,
      ),
  },
  {
    id: "R05",
    severity: "high",
    category: "obfuscation",
    title: "Base64 decoding in executable code",
    description:
      "The code decodes an encoded string and, within a few lines, executes it or sends it over the network. Decoding on its own is ordinary; decoding next to a sink is how payloads are smuggled past review.",
    recommendation: "Decode the string yourself and read what it contains.",
    run: (ctx) => {
      // Decoding base64 is completely routine — JWTs, images, test fixtures.
      // Firing on it alone floods the report on normal repositories, so this
      // rule only reports a decode that sits next to somewhere the decoded
      // bytes could actually do something.
      const decode = /Buffer\.from\([^)]*['"](base64|hex)['"]\)|\batob\s*\(|base64\.b64decode|codecs\.decode\(/;
      const sink =
        /\beval\s*\(|new\s+Function|child_process|execSync|spawn|\.exec\s*\(|fetch\s*\(|https?\.request|writeFileSync|chmod|import\s*\(|require\s*\(/;

      const hits: Hit[] = [];
      for (const [file, content] of ctx.files) {
        if (!/\.(js|ts|cjs|mjs|py|json)$/.test(file)) continue;
        const lines = content.split("\n");
        for (let i = 0; i < lines.length; i++) {
          if (!decode.test(lines[i])) continue;
          const window = lines.slice(Math.max(0, i - 4), i + 5).join("\n");
          if (!sink.test(window)) continue;
          hits.push({ file, line: i + 1, evidence: snip(window, 300) });
          break;
        }
      }
      return hits;
    },
  },
  {
    id: "R06",
    severity: "critical",
    category: "auto-execution",
    title: "VS Code task runs automatically when the folder is opened",
    description:
      "This task has `runOptions.runOn: \"folderOpen\"`. Opening the project in VS Code executes it immediately — before you read a single file, and without running any install command. This is the signature technique of the Contagious Interview campaign.",
    recommendation:
      "Delete `.vscode/` before opening this folder in an editor. If you already opened it, assume the command ran and treat the machine as compromised.",
    run: (ctx) => {
      const content = ctx.files.get(".vscode/tasks.json");
      if (!content) return [];
      return parseVscodeTasks(content)
        .filter((task) => task.runsOnFolderOpen)
        .map((task) => ({
          file: ".vscode/tasks.json",
          evidence: snip(
            `${task.label ?? "task"}: ${task.command ?? ""} ${(task.args ?? []).join(" ")}`,
          ),
        }));
    },
  },
  {
    id: "R06b",
    severity: "medium",
    category: "auto-execution",
    title: "VS Code task defines a shell command",
    description:
      "The project ships editor tasks that run shell commands. These need an explicit trigger, so they are less dangerous than a `folderOpen` task — but they are still code the repo author chose to put one keystroke away.",
    recommendation: "Read each command before using the editor's task runner.",
    run: (ctx) => {
      const content = ctx.files.get(".vscode/tasks.json");
      if (!content) return [];
      return parseVscodeTasks(content)
        .filter((task) => !task.runsOnFolderOpen && task.command)
        .map((task) => ({
          file: ".vscode/tasks.json",
          evidence: snip(`${task.label ?? "task"}: ${task.command}`),
        }));
    },
  },
  {
    id: "R07",
    severity: "high",
    category: "code-execution",
    title: "Foundry FFI is enabled",
    description:
      "`ffi = true` lets Solidity test code call arbitrary shell commands on your machine. Running `forge test` on this repo is equivalent to running whatever its tests decide to run.",
    recommendation:
      "Grep the test suite for `vm.ffi(` and read every call before running `forge test`.",
    run: (ctx) => {
      const content = ctx.files.get("foundry.toml");
      if (!content) return [];
      return tomlValue(content, "ffi") === "true"
        ? [{ file: "foundry.toml", evidence: "ffi = true" }]
        : [];
    },
  },
  {
    id: "R08",
    severity: "high",
    category: "build-script",
    title: "Rust build script executes at compile time",
    description:
      "`build.rs` runs on your machine during `cargo build`, with your permissions, before any of the crate's actual code compiles.",
    recommendation: "Read `build.rs` in full before running any cargo command.",
    run: (ctx) => {
      const hits: Hit[] = [];
      if (ctx.paths.has("build.rs")) {
        hits.push({
          file: "build.rs",
          evidence: snip(ctx.files.get("build.rs")?.slice(0, 400) ?? "build.rs present"),
        });
      }
      const cargo = ctx.files.get("Cargo.toml");
      if (cargo && tomlHasSection(cargo, "build-dependencies")) {
        hits.push({
          file: "Cargo.toml",
          evidence: "[build-dependencies] section present",
        });
      }
      return hits;
    },
  },
  {
    id: "R09",
    severity: "high",
    category: "typosquatting",
    title: "Dependency name closely resembles a popular package",
    description:
      "This dependency's name is within a character or two of a widely used package. Typosquatted packages are published specifically so a misspelling installs an attacker's code instead.",
    recommendation:
      "Check the package on npm: look at its publish date, download count, and repository link. A recent package with few downloads impersonating a popular one is an attack.",
    run: (ctx) => {
      if (!ctx.packageJson) return [];
      const all = {
        ...ctx.packageJson.dependencies,
        ...ctx.packageJson.devDependencies,
        ...ctx.packageJson.optionalDependencies,
      };
      const hits: Hit[] = [];
      for (const [name, version] of Object.entries(all)) {
        if (POPULAR_PACKAGES.includes(name) || KNOWN_GOOD.has(name)) continue;
        // Scoped names carry their own trust anchor: `@acme/react` is not a
        // typosquat of `react`, it is a package published by an org you can
        // check. Squatting happens on the unscoped namespace.
        if (name.startsWith("@")) continue;
        // Short names are dense — almost every three-letter name is within two
        // edits of some popular package. Calibrating against 88 real
        // dependency names, this threshold was the difference between one
        // false positive (`xo` flagged as `zod`) and none.
        //
        // The cost is real: a squat on a four-letter package (`viemm` for
        // `viem`) is not caught here. It cannot be — `nest` and `nuxt` are each
        // one edit from `next`, and all three are legitimate. Short-name squats
        // are left to the AI phase and to the rules that read what the code
        // actually does.
        if (name.length < 5) continue;

        for (const popular of POPULAR_PACKAGES) {
          if (popular.startsWith("@") || popular.length < 5) continue;
          // Allow a second edit only on names long enough for two edits to be
          // a deliberate disguise rather than a coincidence.
          const budget = Math.min(name.length, popular.length) >= 9 ? 2 : 1;
          const distance = editDistance(name, popular);
          if (distance === 0 || distance > budget) continue;

          hits.push({
            file: "package.json",
            // One edit away from a household name is a strong signal; two is
            // worth reading but not worth alarming over.
            severity: distance === 1 ? "high" : "medium",
            evidence: `"${name}": "${version}"  (resembles "${popular}")`,
            description: `The dependency \`${name}\` is ${distance} character${distance === 1 ? "" : "s"} away from \`${popular}\`, a widely used package. Typosquatted packages are published specifically so a near-miss installs an attacker's code instead. Check the package's publish date, download count, and repository link on npm before installing.`,
          });
          break;
        }
      }
      return hits;
    },
  },
  {
    id: "R10",
    severity: "medium",
    category: "supply-chain",
    title: "Dependencies are not pinned and no lockfile is committed",
    description:
      "Without a lockfile and with open version ranges, the code you install today is not the code someone else reviewed yesterday. The repo author can publish a new dependency version at any time and change what runs on your machine.",
    recommendation:
      "Ask for a lockfile. Meanwhile, install with `--ignore-scripts` and review what actually resolved.",
    run: (ctx) => {
      if (!ctx.packageJson) return [];
      const hasLockfile = [
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "bun.lockb",
        "bun.lock",
      ].some((f) => ctx.paths.has(f));
      if (hasLockfile) return [];
      const loose = Object.entries({
        ...ctx.packageJson.dependencies,
        ...ctx.packageJson.devDependencies,
      }).filter(([, version]) => /^[*x]$|^>=|^latest$/.test(version));
      if (loose.length === 0) return [];
      return [
        {
          file: "package.json",
          evidence: snip(
            loose.map(([n, v]) => `"${n}": "${v}"`).join(", "),
          ),
        },
      ];
    },
  },
  {
    id: "R11",
    severity: "high",
    category: "supply-chain",
    title: "Package registry redirected to a non-official server",
    description:
      "`.npmrc` points the installer at a registry that is not npm. Every package you install comes from that server instead — including packages whose names you recognise.",
    recommendation:
      "Do not install. Look up who controls that host before doing anything else.",
    run: (ctx) => {
      const content = ctx.files.get(".npmrc");
      if (!content) return [];

      return parseNpmrc(content).customRegistries.flatMap((r) => {
        // `@acme:registry=...` only redirects that one scope, which is how
        // every company with a private package feed is configured. Redirecting
        // the *global* registry is the attack, because it silently reroutes
        // packages you already trust by name.
        const isScoped = r.key.startsWith("@");
        const knownHost =
          /^https:\/\/(npm\.pkg\.github\.com|[\w.-]*\.(jfrog\.io|artifactory\.[\w.-]+|azure\.com|cloudsmith\.io|gemfury\.com|verdaccio\.[\w.-]+))/.test(
            r.value,
          );
        if (isScoped && knownHost) return [];

        return [{
          file: ".npmrc",
          line: r.line,
          severity: (isScoped ? "medium" : "high") as Severity,
          title: isScoped
            ? "Scoped packages come from a non-standard registry"
            : "Package registry redirected to a non-official server",
          description: isScoped
            ? `Packages under the \`${r.key.split(":")[0]}\` scope are fetched from ${r.value} instead of npm. Private feeds are normal, but check you recognise that host.`
            : undefined,
          evidence: `${r.key}=${r.value}`,
        }];
      });
    },
  },
  {
    id: "R12",
    severity: "high",
    category: "ci",
    title: "Workflow uses `pull_request_target`",
    description:
      "`pull_request_target` runs with repository secrets available and, if it checks out the PR's head, executes untrusted contributor code with access to them.",
    recommendation:
      "Relevant if you fork or contribute. Check whether the workflow checks out `github.event.pull_request.head.sha`.",
    run: (ctx) => {
      const hits: Hit[] = [];
      for (const [file, content] of ctx.files) {
        if (!/^\.github\/workflows\//.test(file)) continue;
        if (parseWorkflow(content).triggers.includes("pull_request_target")) {
          hits.push({ file, evidence: "on: pull_request_target" });
        }
      }
      return hits;
    },
  },
  {
    id: "R13",
    severity: "medium",
    category: "ci",
    title: "GitHub Actions are not pinned to a commit SHA",
    description:
      "Actions referenced by tag or branch can be repointed at new code by whoever owns them, after you have reviewed the workflow.",
    recommendation: "Pin third-party actions to a full commit SHA.",
    run: (ctx) => {
      const hits: Hit[] = [];
      for (const [file, content] of ctx.files) {
        if (!/^\.github\/workflows\//.test(file)) continue;
        for (const a of parseWorkflow(content).unpinnedActions) {
          // First-party actions moving within a major tag is normal practice.
          if (/^actions\//.test(a.action)) continue;
          hits.push({ file, line: a.line, evidence: `uses: ${a.action}` });
        }
      }
      return hits;
    },
  },
  {
    id: "R14",
    severity: "high",
    category: "container",
    title: "Container config grants host access",
    description:
      "A privileged container, or one that mounts the host filesystem or Docker socket, is not a sandbox. Code inside it can reach your real machine.",
    recommendation:
      "Remove the privileged flag and host mounts before running this container, or run it on a disposable VM.",
    run: (ctx) =>
      grepAll(
        ctx,
        /--privileged|privileged:\s*true|\/var\/run\/docker\.sock|-\s*["']?\/:\/|:\s*\/host/,
        /^Dockerfile|docker-compose|\.devcontainer\//,
      ),
  },
  {
    id: "R15",
    severity: "high",
    category: "obfuscation",
    title: "Large encoded blob embedded in source",
    description:
      "A base64 or hex string this long inside source code is not data a human wrote. It is usually a compressed script or binary waiting to be decoded and run.",
    recommendation:
      "Decode it in an isolated environment. `echo '<blob>' | base64 -d | head -c 500` is enough to see what it is.",
    run: (ctx) => {
      const hits: Hit[] = [];
      for (const [file, content] of ctx.files) {
        if (/lock|\.min\.|\.map$/.test(file)) continue;
        const lines = content.split("\n");
        for (let i = 0; i < lines.length; i++) {
          const match = lines[i].match(/[A-Za-z0-9+/=]{500,}|(?:\\x[0-9a-f]{2}){200,}/i);
          if (match) {
            hits.push({
              file,
              line: i + 1,
              evidence: `${match[0].slice(0, 120)}… (${match[0].length} chars)`,
            });
            break;
          }
        }
      }
      return hits;
    },
  },
  {
    id: "R16",
    severity: "critical",
    category: "credential-access",
    title: "Code reads credential and key directories",
    description:
      "The code references paths where SSH keys, cloud credentials, or wallet keypairs live. A coding assignment has no reason to know these paths exist.",
    recommendation:
      "Do not run anything in this repo. Rotate any credentials you believe were already exposed to it.",
    run: (ctx) =>
      grepAll(
        ctx,
        // Three shapes, because real code uses all three: a literal `~/` path,
        // a quoted path segment fed to path.join, and a bare key filename.
        new RegExp(
          [
            String.raw`~[\\/]\.(ssh|aws|gnupg|netrc|kube|config[\\/](solana|gcloud))`,
            String.raw`\.(ssh|aws|gnupg|kube)[\\/]`,
            String.raw`\.config[\\/](solana|gcloud)`,
            String.raw`["'`+"`"+`]\.(ssh|aws|gnupg|netrc)["'`+"`"+`]`,
            String.raw`\bid_(rsa|dsa|ecdsa|ed25519)\b`,
            String.raw`(?:homedir\(\)|expanduser\(|Path\.home\(\)|USERPROFILE)[^\n]{0,80}(?:ssh|aws|gnupg|solana|keychain|credential)`,
            String.raw`LOCALAPPDATA[^\n]*Microsoft[^\n]*Credentials`,
          ].join("|"),
          "i",
        ),
        undefined,
        PROSE_FILES,
      ),
  },
  {
    id: "R17",
    severity: "critical",
    category: "credential-access",
    title: "Code targets cryptocurrency wallet storage",
    description:
      "The code references browser-extension wallet storage or keystore files. This is the payload the Contagious Interview campaign is built to deliver.",
    recommendation:
      "Do not run this. If you already did, move your funds from any hot wallet on this machine now, then rebuild the machine.",
    run: (ctx) =>
      grepAll(
        ctx,
        /wallet\.dat|keystore\/|nkbihfbeogaeaoehlefnkodbefgpgknn|MetaMask|Phantom|bfnaelmomeimhlpmgjnjophhpkkoljpa|Exodus|Ledger\s*Live|id\.json|keypair\.json|mnemonic|seed\s*phrase/i,
        undefined,
        PROSE_FILES,
      ),
  },
  {
    id: "R18",
    severity: "critical",
    category: "backdoor",
    title: "Reverse shell pattern",
    description:
      "This opens an outbound connection and attaches a shell to it, handing interactive control of your machine to whoever is listening.",
    recommendation:
      "Do not run this repo. Report it to GitHub. If it has already run, disconnect the machine from the network.",
    run: (ctx) =>
      grepAll(
        ctx,
        /\/dev\/tcp\/|nc\s+(-[a-z]*e|-e)\b|bash\s+-i\s*>&|socat\s+.*exec|pty\.spawn|Net\.Sockets\.TCPClient/i,
        undefined,
        PROSE_FILES,
      ),
  },
  {
    id: "R19",
    severity: "high",
    category: "obfuscation",
    title: "String built from character codes",
    description:
      "Assembling a string from numeric character codes hides it from anyone reading or grepping the file. Legitimate code has no reason to do this.",
    recommendation: "Decode the array to see what string it produces.",
    run: (ctx) =>
      grepAll(ctx, /fromCharCode\s*\(\s*(?:\d+\s*,\s*){9,}/),
  },
  {
    id: "R20",
    severity: "critical",
    category: "auto-execution",
    title: "SVG file contains executable JavaScript",
    description:
      "This file has an image extension but contains script. SVGs render as HTML in browsers and previews, so 'just looking at the image' can execute it. Lazarus has shipped Node backdoors this way.",
    recommendation:
      "Do not open this file in a browser or preview pane. Read it as text.",
    run: (ctx) => {
      const hits: Hit[] = [];
      for (const [file, content] of ctx.files) {
        if (!file.endsWith(".svg")) continue;
        if (/<script|javascript:|onload\s*=|onerror\s*=|eval\s*\(|require\s*\(/i.test(content)) {
          hits.push({
            file,
            evidence: snip(
              content.match(/<script[\s\S]{0,300}|on(load|error)\s*=[^\s>]{0,200}/i)?.[0] ??
                content.slice(0, 300),
            ),
          });
        }
      }
      return hits;
    },
  },
  {
    id: "R21",
    severity: "critical",
    category: "supply-chain",
    title: "Yarn is reconfigured to run repo-controlled code",
    description:
      "Yarn plugins are arbitrary JavaScript that Yarn loads and executes on every command — including `yarn --version`. A custom registry in `.yarnrc.yml` redirects where every package comes from. Both are set by files committed to this repo.",
    recommendation:
      "Delete `.yarnrc.yml` and `.yarn/plugins/` before running any yarn command in this directory.",
    run: (ctx) => {
      const hits: Hit[] = [];
      for (const path of ctx.paths) {
        if (/^\.yarn\/plugins\/.+\.(c?js)$/.test(path)) {
          hits.push({
            file: path,
            evidence: snip(ctx.files.get(path)?.slice(0, 300) ?? "yarn plugin"),
            description:
              "Yarn loads and executes every plugin in `.yarn/plugins/` on every yarn command, before doing anything else.",
          });
        }
      }
      const yarnrc = ctx.files.get(".yarnrc.yml");
      if (yarnrc) {
        for (const hit of grep(".yarnrc.yml", yarnrc, /npmRegistryServer|npmPublishRegistry|plugins:|checksumBehavior:\s*update|enableScripts:\s*true/)) {
          if (/registry\.yarnpkg\.com|registry\.npmjs\.org/.test(hit.evidence)) continue;
          hits.push(hit);
        }
      }
      return hits;
    },
  },
  {
    id: "R22",
    severity: "critical",
    category: "lifecycle-script",
    title: "Python file executes code at import or install time",
    description:
      "`setup.py` runs during `pip install`. `conftest.py` runs when `pytest` starts. `sitecustomize.py` runs on every Python startup. Code placed here executes without you calling it.",
    recommendation:
      "Read the file before running pip or pytest. Install with `pip install --no-build-isolation --no-binary :none:` only after you have.",
    run: (ctx) => {
      const hits: Hit[] = [];
      for (const name of ["setup.py", "conftest.py", "sitecustomize.py"]) {
        const content = ctx.files.get(name);
        if (!content) continue;
        hits.push(
          ...grep(
            name,
            content,
            /\bos\.system|subprocess\.|\bexec\s*\(|\beval\s*\(|urllib|requests\.(get|post)|socket\.|__import__/,
          ),
        );
      }
      return hits;
    },
  },
  {
    id: "R23",
    severity: "critical",
    category: "obfuscation",
    title: "Bidirectional Unicode control characters in source",
    description:
      "These invisible characters reorder how text is displayed without changing how it is compiled. The code you read in your editor is not the code that runs. This is the Trojan Source attack.",
    recommendation:
      "View the file with `cat -A` or a hex editor to see the real ordering.",
    run: (ctx) => {
      const hits: Hit[] = [];
      // U+202A-U+202E and U+2066-U+2069 reorder rendered text; U+200E/U+200F
      // and U+061C do the same at a smaller scale. None belong in source code.
      const bidi = /[\u202A-\u202E\u2066-\u2069\u200E\u200F\u061C]/;
      const bidiGlobal = /[\u202A-\u202E\u2066-\u2069\u200E\u200F\u061C]/g;
      for (const [file, content] of ctx.files) {
        const lines = content.split("\n");
        for (let i = 0; i < lines.length; i++) {
          if (bidi.test(lines[i])) {
            hits.push({
              file,
              line: i + 1,
              evidence: snip(
                lines[i].replace(bidiGlobal, (c) => `<U+${c.codePointAt(0)!.toString(16).toUpperCase()}>`),
              ),
            });
            break;
          }
        }
      }
      return hits;
    },
  },
  {
    id: "R24",
    severity: "high",
    category: "obfuscation",
    title: "Code hidden beyond the right edge of the screen",
    description:
      "A line padded with hundreds of spaces pushes code far off-screen, where it is invisible to anyone skimming the file in an editor or in GitHub's diff view.",
    recommendation:
      "Open the file with word wrap on, or run `awk 'length > 300' <file>` to see what is out there.",
    run: (ctx) => {
      const hits: Hit[] = [];
      for (const [file, content] of ctx.files) {
        if (/lock|\.min\.|\.map$|\.svg$/.test(file)) continue;
        const lines = content.split("\n");
        for (let i = 0; i < lines.length; i++) {
          const match = lines[i].match(/^(.*?)[ \t]{200,}(\S.*)$/);
          if (match) {
            hits.push({
              file,
              line: i + 1,
              evidence: `…${match[2].slice(0, 200)}  (hidden after ${lines[i].length - match[2].length} blank columns)`,
            });
            break;
          }
        }
      }
      return hits;
    },
  },
  {
    id: "R25",
    severity: "high",
    category: "supply-chain",
    title: "Pre-compiled binary committed to the repository",
    description:
      "A binary in source control cannot be reviewed. Native Node addons (`.node`) and shared libraries load into your process with full permissions the moment something requires them.",
    recommendation:
      "Ask why a source repo ships a binary. Do not run the project until you have an answer you can verify.",
    run: (ctx) =>
      findBinaryArtifacts(ctx.tree).map((entry) => ({
        file: entry.path,
        evidence: `${entry.path} (${entry.size ?? "?"} bytes, not human-readable)`,
      })),
  },
  {
    id: "R26",
    severity: "high",
    category: "supply-chain",
    title: "Lockfile resolves a dependency from outside the registry",
    description:
      "A lockfile entry points at a git repo or an arbitrary tarball URL instead of the package registry. The name in `package.json` looks normal; the code comes from somewhere else entirely.",
    recommendation:
      "Look up who owns that URL. Compare against what `package.json` claims the dependency is.",
    run: (ctx) => {
      const hits: Hit[] = [];
      for (const name of ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"]) {
        const content = ctx.files.get(name);
        if (!content) continue;
        for (const hit of grep(
          name,
          content,
          /(resolved|resolution)"?:?\s*"?(git\+|https?:\/\/(?!registry\.(npmjs\.org|yarnpkg\.com)))/,
        )) {
          hits.push(hit);
          if (hits.length >= 10) break;
        }
      }
      return hits;
    },
  },
  {
    id: "R27",
    severity: "high",
    category: "supply-chain",
    title: "Go module replaced with a third-party fork",
    description:
      "A `replace` directive silently swaps a dependency for a different repository. Imports still read as the original package name.",
    recommendation: "Check who owns each replacement module.",
    run: (ctx) => {
      const content = ctx.files.get("go.mod");
      if (!content) return [];
      return grep("go.mod", content, /^replace\s+\S+\s*=>\s*(?!\.\/|\.\.\/)/);
    },
  },
  {
    id: "R28",
    severity: "high",
    category: "exfiltration",
    title: "Hardcoded exfiltration endpoint",
    description:
      "The code sends data to a chat webhook, paste service, tunnel, or bare IP address. These are the drop points malware uses because they need no infrastructure and blend into normal traffic.",
    recommendation:
      "Find what gets sent to this endpoint. Anything reaching a Discord webhook from a coding assignment is stolen data.",
    run: (ctx) =>
      grepAll(
        ctx,
        /discord(app)?\.com\/api\/webhooks|api\.telegram\.org\/bot|pastebin\.com\/raw|hastebin|transfer\.sh|\.ngrok\.(io|app|free\.dev)|https?:\/\/\d{1,3}(\.\d{1,3}){3}(:\d+)?/i,
      ),
  },
  {
    id: "R29",
    severity: "critical",
    category: "exfiltration",
    title: "Environment variables collected and sent over the network",
    description:
      "The code reads your environment or `.env` file and makes a network request in the same breath. Environment variables are where API keys, database URLs, and private keys live.",
    recommendation:
      "Assume every secret in your shell environment would have been sent. Do not run this; rotate anything already exposed.",
    run: (ctx) => {
      const hits: Hit[] = [];
      const readsEnv =
        /process\.env\b|os\.environ|Object\.keys\(process\.env\)|readFileSync\([^)]*\.env|dotenv/;
      const sendsNetwork =
        /fetch\s*\(|axios\.|https?\.request|XMLHttpRequest|requests\.(post|get)|urllib|net\.connect|WebSocket/;
      for (const [file, content] of ctx.files) {
        if (!/\.(js|ts|cjs|mjs|py)$/.test(file)) continue;
        const lines = content.split("\n");
        for (let i = 0; i < lines.length; i++) {
          if (!readsEnv.test(lines[i])) continue;
          // Same statement, or within a few lines — good enough to flag for AI review.
          const window = lines.slice(Math.max(0, i - 3), i + 4).join("\n");
          if (sendsNetwork.test(window)) {
            hits.push({ file, line: i + 1, evidence: snip(window, 300) });
            break;
          }
        }
      }
      return hits;
    },
  },
  {
    id: "R30",
    severity: "high",
    category: "auto-execution",
    title: "Editor or dev-container config runs commands on open",
    description:
      "Dev container lifecycle hooks (`postCreateCommand`, `postAttachCommand`) and some editor settings execute as soon as the project is opened, without asking.",
    recommendation:
      "Read these commands before opening the folder in VS Code or a dev container.",
    run: (ctx) => {
      const hits: Hit[] = [];
      for (const [file, content] of ctx.files) {
        if (/^\.devcontainer\//.test(file)) {
          hits.push(
            ...grep(file, content, /(postCreate|postStart|postAttach|initialize|onCreate)Command/),
          );
        }
        if (file === ".vscode/settings.json") {
          hits.push(
            ...grep(file, content, /terminal\.integrated\.(env|profiles|automationProfile)|\.executablePath|autoRun/),
          );
        }
        if (/^\.idea\//.test(file)) {
          hits.push(...grep(file, content, /<option name="(SCRIPT_NAME|PROGRAM_PARAMETERS|INTERPRETER_PATH)"/));
        }
      }
      return hits;
    },
  },
  {
    id: "R31",
    severity: "medium",
    category: "obfuscation",
    title: "Minified JavaScript outside a build directory",
    description:
      "A single line of thousands of characters of minified code in a source directory cannot be reviewed. Build output belongs in `dist/`, not next to the source.",
    recommendation:
      "Run it through a formatter and read it, or ask for the unminified source.",
    run: (ctx) => {
      const hits: Hit[] = [];
      for (const [file, content] of ctx.files) {
        if (!/\.(js|cjs|mjs|ts)$/.test(file)) continue;
        if (/^(dist|build|out|public|vendor)\//.test(file) || /\.min\./.test(file)) continue;
        const longest = content
          .split("\n")
          .reduce((max, line) => Math.max(max, line.length), 0);
        if (longest > 5000) {
          hits.push({
            file,
            evidence: `Single line of ${longest} characters — minified or generated code in a source path.`,
          });
        }
      }
      return hits;
    },
  },
  {
    id: "R32",
    severity: "high",
    category: "obfuscation",
    title: "Code has the statistical signature of obfuscation",
    description:
      "This file's character distribution does not look like source code a person wrote. High-entropy, low-whitespace, long-token text is what packers and encoders produce. Heavy obfuscation is self-defeating in this sense: hiding the payload makes the file itself anomalous.",
    recommendation:
      "Run the file through a formatter and read what it actually does. If it cannot be made readable, treat it as hostile.",
    run: (ctx) => {
      const hits: Hit[] = [];
      for (const [file, content] of ctx.files) {
        if (!/\.(js|cjs|mjs|ts|py|json)$/.test(file)) continue;
        // Minified output in a build directory is expected and is not evidence.
        if (/^(dist|build|out|vendor|public)\//.test(file) || /\.min\./.test(file)) continue;
        if (/lock/.test(file)) continue;
        if (content.length < 500) continue;

        const measure = obfuscationScore(content);
        // One strong signal, or every weak signal agreeing.
        if (!measure.strong && measure.score < 4) continue;

        hits.push({
          file,
          evidence: `entropy ${measure.entropy.toFixed(2)} bits/char · ${(measure.whitespace * 100).toFixed(1)}% whitespace · longest token ${measure.longestToken} chars`,
          description:
            (measure.strong
              ? "This file carries a signature that has no legitimate use in source code: "
              : "Every statistical indicator of obfuscation fires on this file: ") +
            measure.reasons.join(", ") +
            ". Ordinary source is around 4.5 bits per character with 15-25% whitespace and human-readable identifiers.",
        });
      }
      return hits;
    },
  },
  {
    id: "R33",
    severity: "high",
    category: "supply-chain",
    title: "Dependency looks like a private package name",
    description:
      "This dependency has an internal-looking name but is resolved from the public registry. If an attacker publishes that name publicly, the installer may prefer it over your organisation's private copy — that is a dependency-confusion attack.",
    recommendation:
      "Confirm whether this package is meant to come from a private registry. If so, the repo needs a scoped `.npmrc` entry pinning it.",
    run: (ctx) => {
      if (!ctx.packageJson) return [];
      const npmrc = ctx.files.get(".npmrc") ?? "";
      const yarnrc = ctx.files.get(".yarnrc.yml") ?? "";

      const hits: Hit[] = [];
      const all = {
        ...ctx.packageJson.dependencies,
        ...ctx.packageJson.devDependencies,
      };
      for (const [name, version] of Object.entries(all)) {
        // Scoped names whose scope has no registry mapping anywhere.
        if (!name.startsWith("@")) continue;
        const scope = name.split("/")[0];
        if (npmrc.includes(`${scope}:registry`) || yarnrc.includes(scope)) continue;
        // Scopes belonging to well-known public orgs are not confusion targets.
        if (/^@(types|babel|eslint|typescript-eslint|next|nomicfoundation|openzeppelin|chainlink|solana|coral-xyz|noble|scure|bufbuild|tanstack|radix-ui|floating-ui|swc|vitest|playwright|storybook|emotion|mui|angular|nestjs|aws-sdk|azure|google-cloud|sentry|octokit|graphql|apollo|prisma|redux|reduxjs|remix-run|sveltejs|vue|nuxt|vercel|smithy|ethersproject|uniswap|aave|safe-global|walletconnect|rainbow-me|wagmi|viem)\b/i.test(scope)) continue;

        hits.push({
          file: "package.json",
          evidence: `"${name}": "${version}"  (scope ${scope} has no registry mapping)`,
        });
      }
      return hits;
    },
  },
  {
    id: "R34",
    severity: "medium",
    category: "supply-chain",
    title: "File extension does not match its contents",
    description:
      "A file whose name says one thing and whose contents say another is how execution gets smuggled past a reviewer skimming a file list — the `.svg` that is really JavaScript, the `.md` that is really a shell script.",
    recommendation: "Open the file as text and read what it really is.",
    run: (ctx) => {
      const hits: Hit[] = [];
      const signatures: [RegExp, RegExp, string][] = [
        [/\.(md|txt|rst)$/i, /^#!\s*\/(bin|usr)/, "shell script with a document extension"],
        [/\.(json)$/i, /^\s*(?:\/\/|function |const |var |require\()/, "JavaScript with a .json extension"],
        [/\.(png|jpe?g|gif|webp|ico)$/i, /^\s*[<{]|require\(|function\s/, "text or code with an image extension"],
        [/\.(css|scss)$/i, /require\(|child_process|eval\s*\(/, "JavaScript inside a stylesheet"],
      ];
      for (const [file, content] of ctx.files) {
        for (const [namePattern, contentPattern, what] of signatures) {
          if (!namePattern.test(file)) continue;
          if (!contentPattern.test(content)) continue;
          hits.push({ file, evidence: `${what}: ${snip(content.slice(0, 200), 200)}` });
          break;
        }
      }
      return hits;
    },
  },
  {
    id: "R35",
    severity: "critical",
    category: "obfuscation",
    title: "String decoded with an XOR loop",
    description:
      "The code walks a string character by character and XORs each one against a key. This is not encryption for security — it is encoding to defeat a reader and a grep. Recent BeaverTail samples layer Base64 and XOR specifically to get past both automated scanners and manual code review.",
    recommendation:
      "Run the decode loop by hand against the encoded string to recover what it produces. Do not run the file to find out.",
    run: (ctx) =>
      grepAll(
        ctx,
        // charCodeAt(...) ^ something, or fromCharCode(... ^ ...) — the two
        // shapes a hand-rolled XOR decoder takes in JavaScript.
        /charCodeAt\s*\([^)]*\)\s*\^|\^\s*\w+\.charCodeAt|fromCharCode\s*\([^)]*\^|ord\s*\([^)]*\)\s*\^/,
        /\.(js|cjs|mjs|ts|py)$/,
      ),
  },
  {
    id: "R36",
    severity: "critical",
    category: "credential-access",
    title: "Code reads browser credential storage",
    description:
      "This reaches into a browser's saved-password database, cookie store, or extension storage. That is where session tokens and wallet extension data live. BeaverTail — the stealer delivered by fake interview repositories — exists to read exactly these paths.",
    recommendation:
      "Do not run this. If it has already run, change the passwords saved in your browser, sign out of every session, and move funds out of any browser wallet.",
    run: (ctx) =>
      grepAll(
        ctx,
        /Login\s?Data|Local\s?State|Cookies\.sqlite|logins\.json|key[34]\.db|Local\s?Extension\s?Settings|IndexedDB[\\/]chrome-extension|security\s+find-generic-password|login\.keychain|Keychains?[\\/]/i,
        undefined,
        PROSE_FILES,
      ),
  },
  {
    id: "R37",
    severity: "high",
    category: "code-execution",
    title: "Downloads a different payload per operating system",
    description:
      "The code branches on the platform or CPU architecture and fetches a matching binary. Legitimate installers do this — but so does a dropper, and a dropper in a coding assignment has no reason to exist. This is the documented behaviour of the fake-interview loaders: check the architecture, pull the right stage, run it.",
    recommendation:
      "Find the URL it downloads from and inspect what is served for your platform, in an isolated environment.",
    run: (ctx) => {
      const hits: Hit[] = [];
      const platform = /process\.(platform|arch)\b|os\.(platform|arch|type)\s*\(|platform\.machine\s*\(|sys\.platform|uname\s+-/;
      const download = /https?:\/\/|curl|wget|fetch\s*\(|urlretrieve|download|axios\.get/i;
      const run = /exec|spawn|child_process|chmod|os\.system|subprocess|Start-Process|\bsh\b|\bbash\b/;

      for (const [file, content] of ctx.files) {
        if (!/\.(js|cjs|mjs|ts|py|sh|bash|ps1)$/.test(file)) continue;
        const lines = content.split("\n");
        for (let i = 0; i < lines.length; i++) {
          if (!platform.test(lines[i])) continue;
          const window = lines.slice(Math.max(0, i - 5), i + 10).join("\n");
          // All three together: branch on platform, fetch something, run it.
          if (!download.test(window) || !run.test(window)) continue;
          hits.push({ file, line: i + 1, evidence: snip(window, 320) });
          break;
        }
      }
      return hits;
    },
  },
];

/**
 * How much a file looks like it was mechanically obfuscated rather than typed.
 *
 * Two kinds of indicator, because they carry very different weight:
 *
 *   Strong — signatures with essentially no legitimate use in source code:
 *     dense `\xNN` escapes, and the `_0xabcd` identifiers that
 *     javascript-obfuscator emits. Either one alone is close to conclusive.
 *
 *   Weak — statistical oddities that also describe minified vendor bundles:
 *     high entropy, no whitespace, enormous tokens, very long lines.
 *
 * A finding needs one strong signal, or all of the weak ones together.
 * Requiring weak signals to agree is what keeps ordinary minified code out;
 * calibrated against real obfuscator output and hand-written TypeScript.
 */
function obfuscationScore(content: string): {
  score: number;
  entropy: number;
  whitespace: number;
  longestToken: number;
  reasons: string[];
  strong: boolean;
} {
  const sample = content.slice(0, 60_000);

  const counts = new Map<string, number>();
  for (const char of sample) counts.set(char, (counts.get(char) ?? 0) + 1);
  let entropy = 0;
  for (const n of counts.values()) {
    const p = n / sample.length;
    entropy -= p * Math.log2(p);
  }

  const whitespace = (sample.match(/\s/g)?.length ?? 0) / sample.length;
  const longestToken = sample
    .split(/[^A-Za-z0-9_$]+/)
    .reduce((max, t) => Math.max(max, t.length), 0);
  const lines = sample.split("\n");
  const longestLine = lines.reduce((max, l) => Math.max(max, l.length), 0);

  // Strong signals.
  const hexEscapes = (sample.match(/\\x[0-9a-fA-F]{2}/g)?.length ?? 0) * 4;
  const hexDensity = hexEscapes / sample.length;
  const packerNames = new Set(sample.match(/_0x[0-9a-f]{4,}/gi) ?? []).size;

  const reasons: string[] = [];
  let strong = false;

  if (hexDensity > 0.02) {
    reasons.push(`${(hexDensity * 100).toFixed(0)}% of the file is \\xNN escapes`);
    strong = true;
  }
  if (packerNames >= 5) {
    reasons.push(`${packerNames} machine-generated _0x identifiers`);
    strong = true;
  }

  let weak = 0;
  if (entropy > 5.0) {
    reasons.push(`high entropy (${entropy.toFixed(2)} bits/char)`);
    weak++;
  }
  if (whitespace < 0.08) {
    reasons.push(`almost no whitespace (${(whitespace * 100).toFixed(1)}%)`);
    weak++;
  }
  if (longestToken > 120) {
    reasons.push(`a ${longestToken}-character unbroken token`);
    weak++;
  }
  if (longestLine > 2000) {
    reasons.push(`a ${longestLine}-character line`);
    weak++;
  }

  return {
    score: strong ? 4 : weak,
    entropy,
    whitespace,
    longestToken,
    reasons,
    strong,
  };
}

/** Run every Phase 1 rule. Pure, fast, no network. */
export function applyRules(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();

  for (const rule of RULES) {
    let hits: Hit[];
    try {
      hits = rule.run(ctx);
    } catch {
      // One malformed file must never take down the scan.
      continue;
    }
    // Two caps, because they solve different noise. The per-file cap stops one
    // hostile file producing eight near-identical rows that all say the same
    // thing; the per-rule cap stops a repo that trips R13 forty times from
    // burying the one finding that matters.
    // `package.json` is one file but many independent facts; a manifest with
    // five typosquatted dependencies should list five, not three.
    const PER_FILE_CAP = rule.category === "typosquatting" ? 8 : 3;
    const perFile = new Map<string, number>();
    let emitted = 0;

    for (const hit of hits) {
      if (emitted >= 8) break;
      const fileCount = perFile.get(hit.file) ?? 0;
      if (fileCount >= PER_FILE_CAP) continue;

      // The evidence is part of the key, not just the location. Rules that
      // report several distinct problems in one file without line numbers —
      // R09 finding four typosquatted dependencies in one package.json, say —
      // would otherwise all collapse onto `R09:package.json:0` and only the
      // first would survive.
      const id = `${rule.id}:${hit.file}:${hit.line ?? 0}:${hit.evidence.slice(0, 120)}`;
      if (seen.has(id)) continue;
      seen.add(id);
      perFile.set(hit.file, fileCount + 1);
      emitted++;
      findings.push({
        id,
        ruleId: rule.id,
        severity: hit.severity ?? rule.severity,
        phase: "static",
        category: rule.category,
        title: hit.title ?? rule.title,
        description: hit.description ?? rule.description,
        file: hit.file,
        line: hit.line,
        evidence: hit.evidence,
        recommendation: rule.recommendation,
      });
    }
  }

  return findings;
}

export function buildRuleContext(
  tree: FileEntry[],
  files: Map<string, string>,
): RuleContext {
  const packageJsonText = files.get("package.json");
  return {
    tree,
    files,
    paths: new Set(tree.filter((e) => e.type === "blob").map((e) => e.path)),
    packageJson: packageJsonText ? parsePackageJson(packageJsonText) : null,
  };
}
