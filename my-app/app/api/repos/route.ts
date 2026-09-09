import { NextResponse } from "next/server";
import { GitHubError, listAccessibleRepos } from "@/lib/github";
import { createFetchClient } from "@/lib/http-fetch";
import { getSession } from "@/lib/session";

/**
 * The repos the signed-in developer can read, most recently pushed first.
 *
 * Collaborations surface first within that ordering: a repo someone else owns
 * and invited you to is both the likeliest thing you came here to scan and the
 * likeliest thing to be hostile.
 */
export async function GET() {
  const session = await getSession();
  if (!session) {
    return NextResponse.json({ error: "Not signed in." }, { status: 401 });
  }

  try {
    const repos = await listAccessibleRepos(session.login, {
      http: createFetchClient(),
      token: session.accessToken,
    });
    repos.sort((a, b) => {
      if (a.isCollaboration !== b.isCollaboration) return a.isCollaboration ? -1 : 1;
      return b.pushedAt.localeCompare(a.pushedAt);
    });
    return NextResponse.json({ repos });
  } catch (error) {
    const code = error instanceof GitHubError ? error.code : "NETWORK";
    const message =
      error instanceof GitHubError ? error.message : "Could not list repositories.";
    return NextResponse.json({ error: message, code }, { status: 502 });
  }
}
