import { NextResponse } from "next/server";
import { fetchViewer } from "@/lib/github";
import { createFetchClient } from "@/lib/http-fetch";
import { appUrl, consumeOAuthState, setSession } from "@/lib/session";

export async function GET(request: Request) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const stateParam = url.searchParams.get("state") ?? "";
  const [state, returnToRaw] = stateParam.split(":");

  const fail = (reason: string) =>
    NextResponse.redirect(`${appUrl()}/scan?auth_error=${encodeURIComponent(reason)}`);

  if (url.searchParams.get("error")) {
    return fail(url.searchParams.get("error_description") ?? "Sign-in was cancelled.");
  }
  if (!code) return fail("GitHub did not return an authorization code.");

  const expected = await consumeOAuthState();
  if (!expected || expected !== state) {
    return fail("Sign-in could not be verified. Please try again.");
  }

  let accessToken: string;
  try {
    const response = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: { accept: "application/json", "content-type": "application/json" },
      body: JSON.stringify({
        client_id: process.env.GITHUB_CLIENT_ID,
        client_secret: process.env.GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: `${appUrl()}/api/auth/github/callback`,
      }),
      cache: "no-store",
    });
    const data = (await response.json()) as {
      access_token?: string;
      error_description?: string;
    };
    if (!data.access_token) {
      return fail(data.error_description ?? "GitHub did not issue a token.");
    }
    accessToken = data.access_token;
  } catch {
    return fail("Could not reach GitHub to complete sign-in.");
  }

  try {
    const viewer = await fetchViewer({ http: createFetchClient(), token: accessToken });
    await setSession({
      accessToken,
      login: viewer.login,
      name: viewer.name,
      avatarUrl: viewer.avatarUrl,
    });
  } catch {
    return fail("Signed in, but GitHub would not return your profile.");
  }

  const returnTo = returnToRaw ? decodeURIComponent(returnToRaw) : "/scan";
  // Only same-origin paths, so a crafted `returnTo` can't bounce the developer
  // off-site carrying a fresh session.
  const safePath = returnTo.startsWith("/") && !returnTo.startsWith("//") ? returnTo : "/scan";
  return NextResponse.redirect(`${appUrl()}${safePath}`);
}
