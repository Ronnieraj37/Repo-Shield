/**
 * Calibration run against real public repositories.
 *
 * Fixtures prove the rules fire on attacks. This proves they stay quiet on
 * ordinary code — which is the harder and more important property, because a
 * scanner that flags everything gets ignored on the one repo that matters.
 *
 *   yarn scan:corpus            # static only
 *   yarn scan:corpus --ai       # include phase 2
 */
import { analyzeRepo } from "../lib/analyzer";
import { fetchFiles, fetchRepoMeta, fetchTree, parseRepoInput } from "../lib/github";
import { createFetchClient } from "../lib/http-fetch";

const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const RED = "\x1b[31m";
const DIM = "\x1b[2m";
const RESET = "\x1b[0m";

/**
 * Widely used projects that a developer would reasonably be asked to work on.
 * Every one of these should come back "safe" — any finding here is a false
 * positive until proven otherwise.
 */
const CORPUS = [
  "expressjs/express",
  "sindresorhus/execa",
  "prettier/prettier",
  "foundry-rs/forge-std",
  "OpenZeppelin/openzeppelin-contracts",
  "vitejs/vite",
  "wevm/viem",
  "typicode/husky",
  "axios/axios",
  "chalk/chalk",
];

async function main() {
  const withAI = process.argv.includes("--ai");
  const http = createFetchClient();
  const token = process.env.GITHUB_TOKEN;
  const geminiApiKey = withAI ? process.env.GEMINI_API_KEY : undefined;

  const ruleCounts = new Map<string, number>();
  const rows: { repo: string; score: number; verdict: string; rules: string[] }[] = [];

  for (const slug of CORPUS) {
    try {
      const parsed = parseRepoInput(slug);
      const repo = await fetchRepoMeta(parsed, { http, token });
      const { tree, truncated } = await fetchTree(repo, { http, token });
      const { contents, considered } = await fetchFiles(repo, tree, { http, token });
      const report = await analyzeRepo(
        { repo, tree, contents, treeTruncated: truncated, filesConsidered: considered },
        { http, geminiApiKey, skipAI: !withAI },
      );

      const rules = [...new Set(report.findings.map((f) => f.ruleId))].sort();
      for (const rule of rules) ruleCounts.set(rule, (ruleCounts.get(rule) ?? 0) + 1);
      rows.push({ repo: slug, score: report.threatScore, verdict: report.verdict, rules });

      const color =
        report.verdict === "safe" ? GREEN : report.verdict === "caution" ? YELLOW : RED;
      console.log(
        `${color}${String(report.threatScore).padStart(3)}${RESET} ${slug.padEnd(38)} ` +
          `${DIM}${report.stats.filesFetched} files${RESET}  ${rules.join(" ") || "-"}`,
      );
      for (const finding of report.findings.slice(0, 4)) {
        console.log(`      ${DIM}${finding.ruleId} ${finding.file} — ${finding.title}${RESET}`);
      }
    } catch (error) {
      console.log(
        `${DIM}  ?  ${slug.padEnd(38)} ${error instanceof Error ? error.message : error}${RESET}`,
      );
    }
  }

  const clean = rows.filter((r) => r.verdict === "safe").length;
  console.log(
    `\n${clean}/${rows.length} scanned clean.  ` +
      `Rules that fired on real code: ${[...ruleCounts.entries()]
        .sort((a, b) => b[1] - a[1])
        .map(([rule, n]) => `${rule}×${n}`)
        .join(" ") || "none"}`,
  );
}

main();
