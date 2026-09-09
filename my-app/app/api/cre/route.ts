import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { NextResponse } from "next/server";
import { creConfigured } from "@/lib/cre";

export const dynamic = "force-dynamic";

/**
 * Build provenance for the CRE workflow.
 *
 * `cre/build-evidence.json` is written by `cre workflow build`, so this is a
 * record of an actual compilation rather than numbers typed into a page. If
 * the file is missing, the page says the workflow has not been built — it does
 * not invent a hash.
 */
export async function GET() {
  let build: unknown = null;
  try {
    const raw = await readFile(
      join(process.cwd(), "cre", "build-evidence.json"),
      "utf8",
    );
    build = JSON.parse(raw);
  } catch {
    // Not built on this machine. The page renders the "not built" state.
  }

  return NextResponse.json({ build, deployed: creConfigured() });
}
