/**
 * Backtest the analyser against real repositories.
 *
 * Fixtures prove the rules fire on attacks. This proves they stay quiet on
 * everything else — which is the harder property, and the one that decides
 * whether anyone believes the tool on the repo that matters.
 *
 * Every repository listed here is a well-known open-source project. Any
 * finding is a false positive until argued otherwise, and any verdict above
 * "safe" is a failure.
 *
 *   yarn backtest            # static only
 *   yarn backtest --ai       # include phase 2
 */
import { analyzeRepo } from "../lib/analyzer";
import { fetchRepoMeta, parseRepoInput } from "../lib/github";
import { fetchRepoArchive } from "../lib/github-archive";
import { createFetchClient } from "../lib/http-fetch";

const G = "\x1b[32m", Y = "\x1b[33m", R = "\x1b[31m", D = "\x1b[2m", B = "\x1b[1m", X = "\x1b[0m";

/** Ordinary projects. Every one of these must come back "safe". */
const CLEAN = [
  // The repository that exposed the vendored-dependency problem: 871 of its
  // 961 files are forge-std and OpenZeppelin checked in under lib/.
  "Ronnieraj37/Kratos",
  // Solidity, heavy on cheatcodes and test vectors that read like malware.
  "foundry-rs/forge-std",
  "OpenZeppelin/openzeppelin-contracts",
  "transmissions11/solmate",
  // Node projects with install hooks, native builds and CI.
  "expressjs/express",
  "sindresorhus/execa",
  "typicode/husky",
  "chalk/chalk",
  "axios/axios",
  "vitejs/vite",
  // Web3 tooling — wallets and keys are the subject matter, not the threat.
  "wevm/viem",
  "ethers-io/ethers.js",
];

async function main() {
  const withAI = process.argv.includes("--ai");
  const http = createFetchClient();
  const token = process.env.GITHUB_TOKEN;
  const geminiApiKey = withAI ? process.env.GEMINI_API_KEY : undefined;

  const ruleHits = new Map<string, number>();
  let failures = 0;
  let scanned = 0;

  console.log(`\n${B}Backtest — every repo below should score "safe"${X}\n`);

  for (const slug of CLEAN) {
    try {
      const repo = await fetchRepoMeta(parseRepoInput(slug), { http, token });
      const archive = await fetchRepoArchive(repo, { http, token }, repo.sizeKb);
      if (!archive) {
        console.log(`${D}  skip  ${slug} — too large for the archive path${X}`);
        continue;
      }

      const report = await analyzeRepo(
        {
          repo,
          tree: archive.tree,
          contents: archive.contents,
          filesConsidered: archive.considered,
        },
        { http, geminiApiKey, skipAI: !withAI },
      );

      scanned++;
      const ok = report.verdict === "safe";
      if (!ok) failures++;

      const colour = ok ? G : report.verdict === "caution" ? Y : R;
      const rules = [...new Set(report.findings.map((f) => f.ruleId))].sort();
      for (const r of rules) ruleHits.set(r, (ruleHits.get(r) ?? 0) + 1);

      console.log(
        `${colour}${String(report.threatScore).padStart(3)}${X} ${slug.padEnd(38)} ` +
          `${D}${report.stats.filesFetched} files${X}  ${rules.join(" ") || "-"}`,
      );
      // Show what actually fired, so a regression is diagnosable from the log.
      for (const f of report.findings.slice(0, 5)) {
        console.log(`      ${D}[${f.severity}] ${f.ruleId} ${f.file}${f.line ? ":" + f.line : ""}${X}`);
      }
    } catch (error) {
      console.log(`${D}  err   ${slug} — ${error instanceof Error ? error.message : error}${X}`);
    }
  }

  console.log(
    `\n${failures === 0 ? G : R}${scanned - failures}/${scanned} clean${X}` +
      (ruleHits.size
        ? `   rules firing on real code: ${[...ruleHits.entries()]
            .sort((a, b) => b[1] - a[1])
            .map(([r, n]) => `${r}×${n}`)
            .join(" ")}`
        : ""),
  );
  console.log();
  if (failures > 0) process.exit(1);
}

main();
