import "server-only";
import { createCipheriv, createDecipheriv, randomBytes, createHash } from "node:crypto";
import { cookies, headers } from "next/headers";

/**
 * Session handling for RepoShield.
 *
 * There is no database and no server-side session store. The GitHub access
 * token lives in exactly one place — an AES-256-GCM sealed, httpOnly cookie in
 * the developer's own browser — and is unsealed per-request, used, and
 * discarded. If this service were breached tomorrow there would be nothing in
 * it to take.
 *
 * That is not a shortcut. It is the claim the product makes, implemented.
 */

const COOKIE_NAME = "rs_session";
const STATE_COOKIE = "rs_oauth_state";
const ALGORITHM = "aes-256-gcm";

/**
 * Sessions last 30 days and roll forward on use.
 *
 * A security tool that logs you out constantly does not read as careful, it
 * reads as broken — and it pushes people toward pasting long-lived tokens
 * instead, which is strictly worse. The token is sealed, httpOnly, and
 * revocable at GitHub on sign-out, so the risk of a long session is bounded;
 * the cost of a short one is that nobody uses the private-repo path at all.
 */
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30;

/**
 * Re-seal the cookie when a session is more than a day old, so an active user
 * never hits the wall. Someone who returns weekly is never logged out; someone
 * who walks away for a month is.
 */
const REFRESH_AFTER_SECONDS = 60 * 60 * 24;

export interface Session {
  accessToken: string;
  login: string;
  name: string | null;
  avatarUrl: string;
  /** Unix seconds. Checked on unseal; an expired session is treated as absent. */
  expiresAt: number;
}

function key(): Buffer {
  const secret = process.env.SESSION_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error(
      "SESSION_SECRET is missing or too short. Generate one with `openssl rand -hex 32` and put it in .env.local.",
    );
  }
  // Hashing accepts a secret of any length while always producing 32 bytes.
  return createHash("sha256").update(secret).digest();
}

export function seal(session: Session): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv(ALGORITHM, key(), iv);
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(session), "utf8"),
    cipher.final(),
  ]);
  return [
    iv.toString("base64url"),
    cipher.getAuthTag().toString("base64url"),
    ciphertext.toString("base64url"),
  ].join(".");
}

export function unseal(sealed: string): Session | null {
  try {
    const [ivPart, tagPart, dataPart] = sealed.split(".");
    if (!ivPart || !tagPart || !dataPart) return null;

    const decipher = createDecipheriv(
      ALGORITHM,
      key(),
      Buffer.from(ivPart, "base64url"),
    );
    decipher.setAuthTag(Buffer.from(tagPart, "base64url"));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(dataPart, "base64url")),
      decipher.final(),
    ]).toString("utf8");

    const session = JSON.parse(plaintext) as Session;
    if (session.expiresAt * 1000 < Date.now()) return null;
    return session;
  } catch {
    // Tampered, truncated, or sealed under a rotated secret. All the same
    // outcome: no session.
    return null;
  }
}

export async function getSession(): Promise<Session | null> {
  const store = await cookies();
  const sealed = store.get(COOKIE_NAME)?.value;
  if (!sealed) return null;

  const session = unseal(sealed);
  if (!session) return null;

  // Rolling expiry. Route handlers can write cookies; server components
  // cannot, so this is wrapped — a read from a component still returns the
  // session, it just does not get to extend it.
  const age = SESSION_TTL_SECONDS - (session.expiresAt - Math.floor(Date.now() / 1000));
  if (age > REFRESH_AFTER_SECONDS) {
    try {
      writeSessionCookie(store, session);
    } catch {
      // Read-only cookie context. Not an error worth surfacing.
    }
  }

  return session;
}

const BASE_COOKIE = {
  httpOnly: true,
  sameSite: "lax" as const,
  secure: process.env.NODE_ENV === "production",
  path: "/",
};

type CookieStore = Awaited<ReturnType<typeof cookies>>;

function writeSessionCookie(
  store: CookieStore,
  session: Omit<Session, "expiresAt">,
): void {
  store.set(
    COOKIE_NAME,
    seal({
      ...session,
      expiresAt: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS,
    }),
    { ...BASE_COOKIE, maxAge: SESSION_TTL_SECONDS },
  );
}

export async function setSession(
  session: Omit<Session, "expiresAt">,
): Promise<void> {
  writeSessionCookie(await cookies(), session);
}

export async function clearSession(): Promise<void> {
  const store = await cookies();
  store.delete(COOKIE_NAME);
}

/** CSRF state for the OAuth round trip. Short-lived and single-use. */
export async function setOAuthState(): Promise<string> {
  const state = randomBytes(24).toString("base64url");
  const store = await cookies();
  store.set(STATE_COOKIE, state, { ...BASE_COOKIE, maxAge: 600 });
  return state;
}

export async function consumeOAuthState(): Promise<string | null> {
  const store = await cookies();
  const state = store.get(STATE_COOKIE)?.value ?? null;
  store.delete(STATE_COOKIE);
  return state;
}

/**
 * Which GitHub token to use for a request, in order of the user's intent.
 *
 * A pasted token wins over the session because a developer who typed one in
 * this box meant to use *that* one — usually a narrowly scoped throwaway. The
 * server's own token is last and only widens the anonymous rate limit; it is
 * never used to read anything the caller could not read themselves.
 */
export async function resolveToken(pastedToken?: string): Promise<{
  token?: string;
  source: "pasted" | "session" | "server" | "anonymous";
}> {
  if (pastedToken?.trim()) {
    return { token: pastedToken.trim(), source: "pasted" };
  }
  const session = await getSession();
  if (session) return { token: session.accessToken, source: "session" };
  if (process.env.GITHUB_TOKEN) {
    return { token: process.env.GITHUB_TOKEN, source: "server" };
  }
  return { source: "anonymous" };
}

/**
 * The origin this app is actually being served from.
 *
 * This has to be exact: it becomes the OAuth `redirect_uri`, and GitHub
 * rejects the whole sign-in when it does not match a registered callback URL,
 * character for character.
 *
 * Reading it from a single env var was a trap. A deployment that forgot to set
 * `NEXT_PUBLIC_APP_URL` silently fell back to `http://localhost:3000` and sent
 * that to GitHub from a public URL — which fails with "The redirect_uri is not
 * associated with this application", an error that says nothing about the
 * actual cause. Deriving it from the request instead means localhost and
 * production are both right with no configuration at all.
 *
 * Order matters:
 *   1. an explicit override, for when the public origin differs from the one
 *      requests arrive on (a proxy, a custom domain)
 *   2. Vercel's stable production domain — preview deployments get unique
 *      hostnames that will never be registered as callbacks, so OAuth from a
 *      preview should still return to production
 *   3. the request's own host, which covers local development
 */
export async function appUrl(): Promise<string> {
  const explicit = process.env.NEXT_PUBLIC_APP_URL?.trim();
  if (explicit) return explicit.replace(/\/$/, "");

  const productionDomain = process.env.VERCEL_PROJECT_PRODUCTION_URL?.trim();
  if (productionDomain) return `https://${productionDomain.replace(/\/$/, "")}`;

  try {
    const store = await headers();
    const host = store.get("x-forwarded-host") ?? store.get("host");
    if (host) {
      const proto =
        store.get("x-forwarded-proto") ??
        (host.startsWith("localhost") || host.startsWith("127.0.0.1")
          ? "http"
          : "https");
      return `${proto}://${host}`;
    }
  } catch {
    // Called outside a request scope; fall through to the dev default.
  }

  return "http://localhost:3000";
}
