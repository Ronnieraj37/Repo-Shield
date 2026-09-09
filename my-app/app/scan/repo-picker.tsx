"use client";

import { useEffect, useState } from "react";
import { AlertTriangle, Lock, Users } from "lucide-react";
import { GithubMark } from "@/components/github-mark";
import Link from "next/link";
import type { RepoSummary } from "@/lib/github";

/**
 * Repos the signed-in developer can read, freshest first.
 *
 * This exists because of one specific moment: a "recruiter" invites you to a
 * private repo, you come here, and the thing you want to scan is already the
 * top row. Pasting a URL is the fallback, not the main path.
 */
interface RateLimit {
  remaining: number;
  limit: number;
  resetAt: string;
}

/**
 * Below this many requests left, a scan is likely to fail partway through — a
 * single scan costs roughly ten calls. Warning first is much better than
 * letting someone watch a progress bar die.
 */
const LOW_BUDGET = 15;

export function RepoPicker() {
  const [repos, setRepos] = useState<RepoSummary[] | null>(null);
  const [state, setState] = useState<"loading" | "anonymous" | "ready" | "error">(
    "loading",
  );
  const [signInAvailable, setSignInAvailable] = useState(false);
  const [rateLimit, setRateLimit] = useState<RateLimit | null>(null);

  useEffect(() => {
    let cancelled = false;

    (async () => {
      const me = await fetch("/api/me")
        .then((r) => r.json())
        .catch(() => null);
      if (cancelled) return;

      setSignInAvailable(Boolean(me?.signInAvailable));
      setRateLimit((me?.rateLimit as RateLimit | undefined) ?? null);
      if (!me?.user) {
        setState("anonymous");
        return;
      }

      const data = await fetch("/api/repos")
        .then((r) => (r.ok ? r.json() : null))
        .catch(() => null);
      if (cancelled) return;

      if (!data?.repos) {
        setState("error");
        return;
      }
      setRepos(data.repos as RepoSummary[]);
      setState("ready");
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  if (state === "loading") return null;

  const budget =
    rateLimit && rateLimit.remaining < LOW_BUDGET ? (
      <div
        className="panel flex gap-3 p-4"
        style={{ borderColor: "var(--color-medium)" }}
      >
        <AlertTriangle size={16} className="mt-0.5 shrink-0 text-[var(--color-medium)]" />
        <div className="text-sm leading-relaxed text-[var(--color-muted)]">
          <p>
            {rateLimit.remaining === 0
              ? "GitHub's API budget for this server is used up."
              : `Only ${rateLimit.remaining} GitHub API requests left, and a scan costs about ten.`}{" "}
            It resets at{" "}
            {new Date(rateLimit.resetAt).toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
            })}
            .
          </p>
          <p className="mt-1.5 text-xs text-[var(--color-faint)]">
            {signInAvailable
              ? "Sign in with GitHub for your own 5,000/hour limit, or paste a token above."
              : "Set GITHUB_TOKEN on the server, or paste a token above, to raise it to 5,000/hour."}
          </p>
        </div>
      </div>
    ) : null;

  if (state === "anonymous") {
    return (
      <>
        {budget}
        <div className="panel p-5">
        <h2 className="text-sm font-medium">Scanning something private?</h2>
        <p className="mt-2 max-w-xl text-sm leading-relaxed text-[var(--color-muted)]">
          Sign in and the repositories you have been invited to appear here,
          newest first — no URL to paste. Your token is stored encrypted in a
          cookie in your own browser, and signing out revokes this app&apos;s
          access at GitHub.
        </p>
        {signInAvailable ? (
          <a href="/api/auth/github?returnTo=/scan" className="btn btn-ghost mt-4">
            <GithubMark />
            Sign in with GitHub
          </a>
        ) : (
          <p className="mt-3 text-xs leading-relaxed text-[var(--color-muted)]">
            Sign-in is not available on this deployment, so the repository list
            cannot be shown. You can still scan a private repository by pasting
            your own GitHub token above — it is used for that one scan and never
            stored.
          </p>
        )}
        </div>
      </>
    );
  }

  if (state === "error" || !repos) {
    return (
      <p className="text-sm text-[var(--color-muted)]">
        Could not load your repositories. Paste a URL above instead.
      </p>
    );
  }

  const invited = repos.filter((r) => r.isCollaboration);
  const own = repos.filter((r) => !r.isCollaboration);

  return (
    <div className="space-y-6">
      {budget}
      {invited.length > 0 ? (
        <Group
          title="Repositories you were invited to"
          hint="Someone else owns these. If you were sent a coding assignment, it is here."
          repos={invited}
          highlight
        />
      ) : null}
      {own.length > 0 ? (
        <Group title="Your repositories" repos={own.slice(0, 8)} />
      ) : null}
    </div>
  );
}

function Group({
  title,
  hint,
  repos,
  highlight,
}: {
  title: string;
  hint?: string;
  repos: RepoSummary[];
  highlight?: boolean;
}) {
  return (
    <section>
      <h2 className="flex items-center gap-2 text-sm font-medium">
        {highlight ? <Users size={14} className="text-[var(--color-medium)]" /> : null}
        {title}
      </h2>
      {hint ? (
        <p className="mt-1 text-xs text-[var(--color-muted)]">{hint}</p>
      ) : null}
      <ul className="mt-3 space-y-1.5">
        {repos.map((repo) => (
          <li key={repo.fullName}>
            <Link
              href={`/scan?repo=${encodeURIComponent(repo.fullName)}`}
              className="panel flex items-center gap-3 px-4 py-2.5 transition-colors hover:bg-[var(--color-surface-2)]"
            >
              <span className="truncate font-mono text-sm">{repo.fullName}</span>
              {repo.isPrivate ? (
                <Lock size={12} className="shrink-0 text-[var(--color-faint)]" />
              ) : null}
              <span className="ml-auto shrink-0 font-mono text-[0.7rem] text-[var(--color-faint)]">
                {relativeTime(repo.pushedAt)}
              </span>
            </Link>
          </li>
        ))}
      </ul>
    </section>
  );
}

function relativeTime(iso: string): string {
  const seconds = (Date.now() - new Date(iso).getTime()) / 1000;
  const units: [number, string][] = [
    [60, "s"],
    [3600, "m"],
    [86400, "h"],
    [2592000, "d"],
    [31536000, "mo"],
  ];
  if (seconds < 60) return "just now";
  for (let i = 1; i < units.length; i++) {
    if (seconds < units[i][0]) {
      return `${Math.floor(seconds / units[i - 1][0])}${units[i - 1][1]} ago`;
    }
  }
  return `${Math.floor(seconds / 31536000)}y ago`;
}
