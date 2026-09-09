/**
 * Live check of Phase 2 against the real Gemini API.
 *
 * Runs the full pipeline (static + AI) over the bundled fixtures and prints
 * what the model added. Costs a few cents; not part of `test:analyzer`.
 *
 *   yarn test:ai
 */
import { analyzeRepo } from "../lib/analyzer";
import { createFetchClient } from "../lib/http-fetch";
import { SAMPLES, sampleToAnalyzeInput } from "../lib/samples";

const RESET = "\x1b[0m";
const DIM = "\x1b[2m";
const BOLD = "\x1b[1m";

async function main() {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    console.error("GEMINI_API_KEY is not set. Run with `yarn test:ai`.");
    process.exit(1);
  }

  for (const sample of SAMPLES) {
    console.log(`\n${BOLD}${sample.slug}${RESET}`);
    const started = Date.now();
    const report = await analyzeRepo(sampleToAnalyzeInput(sample), {
      geminiApiKey: apiKey,
      http: createFetchClient(),
    });

    console.log(
      `  ${report.threatScore}/100 "${report.verdict}" - ` +
        `${report.stats.filesFlagged} flagged, ${report.stats.filesAnalyzedByAI} sent to AI - ` +
        `${((Date.now() - started) / 1000).toFixed(1)}s`,
    );
    if (report.degraded.length) {
      console.log(`  ${DIM}degraded: ${report.degraded.join(" | ")}${RESET}`);
    }

    console.log(`\n  summary: ${report.summary}\n`);

    const ai = report.findings.filter((f) => f.phase === "ai");
    console.log(`  ${ai.length} AI-only findings:`);
    for (const f of ai) {
      console.log(`    [${f.severity}] ${f.file} - ${f.title}`);
      console.log(`      ${DIM}${f.description.slice(0, 220)}${RESET}`);
    }

    const confirmed = report.findings.filter(
      (f) => f.phase === "static" && f.confirmedByAI,
    );
    console.log(`  ${confirmed.length} static findings confirmed by AI`);
  }
}

main();
