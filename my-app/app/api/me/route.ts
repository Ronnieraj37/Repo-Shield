import { NextResponse } from "next/server";
import { fetchRateLimit } from "@/lib/github";
import { createFetchClient } from "@/lib/http-fetch";
import { creConfigured } from "@/lib/cre";
import { getSession } from "@/lib/session";

export async function GET() {
  const session = await getSession();
  const rateLimit = await fetchRateLimit({
    http: createFetchClient(),
    token: session?.accessToken ?? process.env.GITHUB_TOKEN,
  });

  return NextResponse.json({
    user: session
      ? { login: session.login, name: session.name, avatarUrl: session.avatarUrl }
      : null,
    expiresAt: session?.expiresAt ?? null,
    signInAvailable: Boolean(process.env.GITHUB_CLIENT_ID),
    confidentialAvailable: creConfigured(),
    rateLimit,
  });
}
