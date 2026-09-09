/**
 * Regression check for the analysis pipeline, run against the bundled samples.
 *
 * Phase 1 only - no API key, no network. If this passes, the static engine is
 * intact; the AI phase is additive and fails open by design.
 *
 *   yarn test:analyzer
 */
import { analyzeRepo } from "../lib/analyzer";
import { SAMPLES, sampleToAnalyzeInput } from "../lib/samples";

const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const BOLD = "\x1b[1m";
const RESET = "\x1b[0m";

/** Rules each sample must trip. Add to these when adding a rule. */
const MUST_DETECT: Record<string, string[]> = {
  "contagious-interview": [
    "R06",
    "R01",
    "R02",
    "R11",
    "R16",
    "R17",
    "R20",
    "R28",
  ],
  "subtle-supply-chain": ["R21", "R07", "R24"],
  "clean-project": [],
  "benign-tooling": [],
};

/** Rules that firing on a sample would be a false positive. */
const MUST_NOT_DETECT: Record<string, string[]> = {
  "clean-project": [
    "R01",
    "R02",
    "R06",
    "R11",
    "R16",
    "R17",
    "R18",
    "R20",
    "R21",
  ],
  // The false-positive fixture: every rule listed here has something in that
  // repo a naive version of it would match on — an install hook, a private
  // registry, base64, child_process, an SVG, a Dockerfile, unpinned actions.
  "benign-tooling": [
    "R01",
    "R02",
    "R03",
    "R04",
    "R05",
    "R06",
    "R09",
    "R11",
    "R14",
    "R16",
    "R17",
    "R18",
    "R20",
    "R25",
    "R26",
    "R29",
    "R31",
  ],
};

let failures = 0;

function check(condition: boolean, message: string) {
  const label = condition ? `${GREEN}PASS${RESET}` : `${RED}FAIL${RESET}`;
  console.log(`  ${label} ${message}`);
  if (!condition) failures++;
}

async function main() {
  for (const sample of SAMPLES) {
    console.log(
      `\n${BOLD}${sample.slug}${RESET} - expecting "${sample.expectedVerdict}"`,
    );

    const report = await analyzeRepo(sampleToAnalyzeInput(sample), {
      skipAI: true,
    });
    const rules = new Set(report.findings.map((f) => f.ruleId));

    console.log(
      `  score ${report.threatScore}/100 - verdict "${report.verdict}" - ` +
        `${report.findings.length} findings - rules: ${[...rules].sort().join(", ") || "none"}`,
    );

    check(
      report.verdict === sample.expectedVerdict,
      `verdict is "${sample.expectedVerdict}"`,
    );

    for (const ruleId of MUST_DETECT[sample.slug] ?? []) {
      check(rules.has(ruleId), `detects ${ruleId}`);
    }
    for (const ruleId of MUST_NOT_DETECT[sample.slug] ?? []) {
      check(!rules.has(ruleId), `does not false-positive ${ruleId}`);
    }

    check(report.actionPlan.length > 0, "produces an action plan");
    check(report.summary.length > 40, "produces a summary");
    check(
      /^[0-9a-f]{16}$/.test(report.id),
      "produces a deterministic report id",
    );
  }

  if (failures === 0) {
    console.log(`\n${GREEN}All analyzer checks passed.${RESET}\n`);
  } else {
    console.log(`\n${RED}${failures} check(s) failed.${RESET}\n`);
    process.exit(1);
  }
}

main();
