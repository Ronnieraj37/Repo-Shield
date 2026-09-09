"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useCallback, useEffect, useRef, useState } from "react";
import { AlertCircle, Check, KeyRound, Lock, Loader2 } from "lucide-react";
import { GithubMark } from "@/components/github-mark";
import type { Finding, ScanEvent } from "@/lib/analyzer/types";
import { ScanBox } from "@/components/scan-box";
import { SeverityBadge } from "@/components/severity";
import { saveReport } from "@/lib/store";
import { RepoPicker } from "./repo-picker";

interface StageLine {
  message: string;
  detail?: string;
}

type Status = "idle" | "running" | "error";

export function ScanConsole() {
  const router = useRouter();
  const params = useSearchParams();
  const repo = params.get("repo");
  const sample = params.get("sample");
  const mode = params.get("mode") === "confidential" ? "confidential" : undefined;
  const authError = params.get("auth_error");

  const target = sample
    ? `sample:${sample}`
    : repo
      ? `repo:${repo}${mode ? ":confidential" : ""}`
      : null;

  const [status, setStatus] = useState<Status>(target ? "running" : "idle");
  const [stages, setStages] = useState<StageLine[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState<{ code: string; message: string } | null>(null);
  const [renderedTarget, setRenderedTarget] = useState(target);
  const [signInAvailable, setSignInAvailable] = useState<boolean | null>(null);
  const startedFor = useRef<string | null>(null);

  // Adjusting state during render, rather than in an effect, is React's own
  // answer to "reset when the input changes": it happens in the same pass, so
  // there is no flash of the previous scan's stages and no cascading render.
  if (target !== renderedTarget) {
    setRenderedTarget(target);
    setStatus(target ? "running" : "idle");
    setStages([]);
    setFindings([]);
    setError(null);
  }

  // Whether this server can actually perform an OAuth sign-in. Offering the
  // button when it cannot sends the developer to a 501 with no way back — the
  // single worst thing a security tool can do at the moment someone is already
  // nervous about a repository.
  useEffect(() => {
    let cancelled = false;
    fetch("/api/me")
      .then((r) => r.json())
      .then((me: { signInAvailable?: boolean }) => {
        if (!cancelled) setSignInAvailable(Boolean(me.signInAvailable));
      })
      .catch(() => {
        if (!cancelled) setSignInAvailable(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const run = useCallback(
    async (body: Record<string, string>) => {
      try {
        const response = await fetch("/api/scan", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
        });

        if (!response.body) {
          setError({ code: "NETWORK", message: "The server sent no response." });
          setStatus("error");
          return;
        }

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";

        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });

          // SSE frames are separated by a blank line; anything after the last
          // one is a partial frame we hold until the next chunk.
          const frames = buffer.split("\n\n");
          buffer = frames.pop() ?? "";

          for (const frame of frames) {
            const line = frame.split("\n").find((l) => l.startsWith("data: "));
            if (!line) continue;
            let event: ScanEvent;
            try {
              event = JSON.parse(line.slice(6)) as ScanEvent;
            } catch {
              continue;
            }
            handleEvent(event);
          }
        }
      } catch {
        setError({
          code: "NETWORK",
          message: "The connection dropped before the scan finished.",
        });
        setStatus("error");
      }

      function handleEvent(event: ScanEvent) {
        if (event.type === "stage") {
          setStages((prev) => {
            // Repeated progress on the same stage replaces the line rather
            // than stacking twenty near-identical rows.
            const last = prev[prev.length - 1];
            if (last?.message === event.message) {
              return [...prev.slice(0, -1), { message: event.message, detail: event.detail }];
            }
            return [...prev, { message: event.message, detail: event.detail }];
          });
        } else if (event.type === "finding") {
          setFindings((prev) => [...prev, event.finding]);
        } else if (event.type === "error") {
          setError({ code: event.code, message: event.message });
          setStatus("error");
        } else if (event.type === "done") {
          saveReport(event.report);
          router.replace(`/report/${event.report.id}`);
        }
      }
    },
    [router],
  );

  // `run` opens an SSE stream and updates state from its callbacks, which is
  // the subscribe-to-an-external-system case effects exist for. Every setState
  // inside it happens after an `await`, but the lint rule cannot see across the
  // async boundary and reports it as a synchronous call.
  /* eslint-disable react-hooks/set-state-in-effect */
  useEffect(() => {
    if (!target || startedFor.current === target) return;
    startedFor.current = target;

    if (sample) {
      void run({ sample });
      return;
    }

    // A pasted token is handed over once, then removed — it should not survive
    // into the next scan the developer runs from this tab.
    let token: string | undefined;
    try {
      token = sessionStorage.getItem("reposhield.token") ?? undefined;
      sessionStorage.removeItem("reposhield.token");
    } catch {
      token = undefined;
    }
    void run({
      repo: repo!,
      ...(token ? { token } : {}),
      ...(mode ? { mode } : {}),
    });
  }, [target, repo, sample, mode, run]);
  /* eslint-enable react-hooks/set-state-in-effect */

  if (status === "idle" && !repo && !sample) {
    return (
      <div className="space-y-8">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Scan a repository</h1>
          <p className="mt-2 text-sm text-[var(--color-muted)]">
            Public repositories work without signing in.
          </p>
        </div>
        {authError ? (
          <ErrorPanel code="AUTH" message={authError} signInAvailable={signInAvailable} />
        ) : null}
        <ScanBox autoFocus />
        <RepoPicker />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        {status === "error" ? (
          <AlertCircle size={18} className="text-[var(--color-critical)]" />
        ) : (
          <Loader2 size={18} className="animate-spin text-[var(--color-accent)]" />
        )}
        <h1 className="truncate font-mono text-sm">
          {sample ? `sample: ${sample}` : repo}
        </h1>
        {mode ? (
          <span className="ml-auto shrink-0 rounded px-2 py-0.5 font-mono text-[0.65rem] uppercase tracking-wider text-[var(--color-accent)] ring-1 ring-[var(--color-accent-dim)]">
            confidential
          </span>
        ) : null}
      </div>

      <div className="panel overflow-hidden">
        {status === "running" ? (
          <div className="h-0.5 overflow-hidden bg-[var(--color-border)]">
            <div className="animate-sweep h-full w-1/3 bg-[var(--color-accent)]" />
          </div>
        ) : null}
        <ol className="space-y-2.5 p-5 font-mono text-xs">
          {stages.map((stage, index) => {
            const isLast = index === stages.length - 1;
            const pending = isLast && status === "running";
            return (
              <li key={`${stage.message}-${index}`} className="flex items-center gap-2.5">
                {pending ? (
                  <span className="animate-pulse-dot size-1.5 rounded-full bg-[var(--color-accent)]" />
                ) : (
                  <Check size={12} className="text-[var(--color-accent)]" />
                )}
                <span className={pending ? "text-[var(--color-text)]" : "text-[var(--color-muted)]"}>
                  {stage.message}
                </span>
                {stage.detail ? (
                  <span className="text-[var(--color-faint)]">· {stage.detail}</span>
                ) : null}
              </li>
            );
          })}
          {stages.length === 0 && status === "running" ? (
            <li className="text-[var(--color-faint)]">Connecting…</li>
          ) : null}
        </ol>
      </div>

      {findings.length > 0 ? (
        <div className="panel p-5">
          <p className="font-mono text-[0.65rem] uppercase tracking-[0.16em] text-[var(--color-faint)]">
            Found so far
          </p>
          <ul className="mt-3 space-y-2">
            {findings.slice(-6).map((finding) => (
              <li key={finding.id} className="animate-fade-up flex items-center gap-2.5 text-sm">
                <SeverityBadge severity={finding.severity} />
                <span className="truncate text-[var(--color-muted)]">{finding.title}</span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {error ? (
        <ErrorPanel
          code={error.code}
          message={error.message}
          repo={repo}
          signInAvailable={signInAvailable}
        />
      ) : null}
    </div>
  );
}

/**
 * Error states carry the next action, not just the failure.
 *
 * "Repository not found" and "this repo is private and you are not signed in"
 * look identical coming from GitHub, but they need completely different
 * responses from the developer. Conflating them is the most common way a tool
 * like this wastes someone's time.
 */
function ErrorPanel({
  code,
  message,
  repo,
  signInAvailable,
}: {
  code: string;
  message: string;
  repo?: string | null;
  /** `null` while unknown — render neither branch rather than guessing. */
  signInAvailable: boolean | null;
}) {
  const returnTo = repo ? `/scan?repo=${encodeURIComponent(repo)}` : "/scan";
  const wantsAuth = code === "NEEDS_AUTH" || code === "RATE_LIMITED";

  return (
    <div className="panel p-5" style={{ borderColor: "var(--color-critical)" }}>
      <div className="flex items-start gap-3">
        <AlertCircle size={16} className="mt-0.5 shrink-0 text-[var(--color-critical)]" />
        <div className="min-w-0 flex-1">
          <p className="text-sm leading-relaxed">{message}</p>

          {code === "NEEDS_AUTH" && signInAvailable === true ? (
            <div className="mt-4 space-y-3">
              <a
                href={`/api/auth/github?returnTo=${encodeURIComponent(returnTo)}`}
                className="btn btn-primary"
              >
                <GithubMark />
                Sign in with GitHub
              </a>
              <p className="flex items-start gap-2 text-xs leading-relaxed text-[var(--color-muted)]">
                <Lock size={13} className="mt-0.5 shrink-0" />
                <span>
                  GitHub has no read-only scope that can reach a private repo you
                  were invited to, so this asks for the <code className="font-mono">repo</code>{" "}
                  scope — read and write on your private repositories. We use it to
                  read files and nothing else, it is stored encrypted in a cookie in
                  your browser, and signing out revokes the grant at GitHub. If you
                  would rather not,{" "}
                  <Link href="/scan" className="text-[var(--color-accent)] hover:underline">
                    paste a token instead
                  </Link>
                  .
                </span>
              </p>
            </div>
          ) : null}

          {code === "RATE_LIMITED" && signInAvailable === true ? (
            <a
              href={`/api/auth/github?returnTo=${encodeURIComponent(returnTo)}`}
              className="btn btn-ghost mt-4"
            >
              <GithubMark />
              Sign in for a higher limit
            </a>
          ) : null}

          {wantsAuth && signInAvailable === false ? (
            <div className="mt-4 rounded-lg border border-[var(--color-border-strong)] bg-[var(--color-surface-2)] p-3.5">
              <p className="flex items-center gap-1.5 text-sm font-medium">
                <KeyRound size={13} className="text-[var(--color-medium)]" />
                Use your own GitHub token
              </p>
              <p className="mt-1.5 text-xs leading-relaxed text-[var(--color-muted)]">
                Sign-in is not set up on this server, so this is the way through.
                Create a{" "}
                <a
                  href="https://github.com/settings/tokens/new?scopes=repo&description=RepoShield%20scan"
                  target="_blank"
                  rel="noreferrer"
                  className="text-[var(--color-accent)] hover:underline"
                >
                  classic token
                </a>{" "}
                — <code className="font-mono">repo</code> scope for a private
                repository, or no scopes at all if you only need a higher rate
                limit. It is used for one request and never stored.
              </p>
              <Link href="/scan" className="btn btn-ghost mt-3">
                Paste a token and retry
              </Link>
            </div>
          ) : null}

          {code === "CRE_UNAVAILABLE" ? (
            <Link href={repo ? `/scan?repo=${encodeURIComponent(repo)}` : "/scan"} className="btn btn-ghost mt-4">
              Run a standard scan instead
            </Link>
          ) : null}

          {code === "INVALID_INPUT" ? (
            <p className="mt-3 font-mono text-xs text-[var(--color-faint)]">
              Accepted: github.com/owner/repo · owner/repo · git@github.com:owner/repo.git
            </p>
          ) : null}

          {code === "NOT_FOUND" ? (
            <p className="mt-3 flex items-center gap-1.5 text-xs text-[var(--color-muted)]">
              <KeyRound size={12} />
              If you know it exists, your account may not have been granted access yet.
            </p>
          ) : null}

          <Link href="/scan" className="btn btn-ghost mt-4">
            Try another repository
          </Link>
        </div>
      </div>
    </div>
  );
}
