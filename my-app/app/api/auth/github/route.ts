import { NextResponse } from "next/server";
import { appUrl, setOAuthState } from "@/lib/session";

/**
 * Start the GitHub OAuth flow.
 *
 * Scope note: `repo` is the only scope GitHub offers that can read a private
 * repository you were invited to as an outside collaborator — there is no
 * read-only equivalent, and fine-grained tokens cannot reach repos owned by
 * someone else. So we ask for the scope the job requires, say plainly on the
 * sign-in page what it grants, and revoke it properly on sign-out.
 */
export async function GET(request: Request) {
  const clientId = process.env.GITHUB_CLIENT_ID;
  if (!clientId) {
    return NextResponse.json(
      { error: "GitHub sign-in is not configured on this server." },
      { status: 501 },
    );
  }

  const returnTo = new URL(request.url).searchParams.get("returnTo") ?? "/scan";
  const state = await setOAuthState();

  const authorize = new URL("https://github.com/login/oauth/authorize");
  authorize.searchParams.set("client_id", clientId);
  authorize.searchParams.set("redirect_uri", `${appUrl()}/api/auth/github/callback`);
  authorize.searchParams.set("scope", "read:user repo");
  // The return path rides along in `state` so the callback can send the
  // developer back where they were without a second cookie.
  authorize.searchParams.set("state", `${state}:${encodeURIComponent(returnTo)}`);

  return NextResponse.redirect(authorize.toString());
}
