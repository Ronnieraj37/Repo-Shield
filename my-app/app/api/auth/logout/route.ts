import { NextResponse } from "next/server";
import { clearSession, getSession } from "@/lib/session";

/**
 * Sign out, and actually mean it.
 *
 * Deleting our cookie would leave the OAuth grant sitting in the developer's
 * GitHub account indefinitely. We ask GitHub to delete the grant itself, so
 * after this the app has no standing access at all — verifiable by the user at
 * github.com/settings/applications.
 */
export async function POST() {
  const session = await getSession();

  if (session) {
    const clientId = process.env.GITHUB_CLIENT_ID;
    const clientSecret = process.env.GITHUB_CLIENT_SECRET;
    if (clientId && clientSecret) {
      try {
        await fetch(`https://api.github.com/applications/${clientId}/grant`, {
          method: "DELETE",
          headers: {
            accept: "application/vnd.github+json",
            authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`,
            "x-github-api-version": "2022-11-28",
          },
          body: JSON.stringify({ access_token: session.accessToken }),
        });
      } catch {
        // Revocation is best-effort; the cookie still goes either way, and the
        // token expires from our side regardless.
      }
    }
  }

  await clearSession();
  return NextResponse.json({ ok: true, revoked: Boolean(session) });
}
