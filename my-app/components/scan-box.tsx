"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { ArrowRight, KeyRound, Search, ShieldCheck } from "lucide-react";

/**
 * The input. Accepts anything that identifies a repo and hands off to /scan.
 *
 * The pasted-token field is collapsed by default but present on every scan
 * box, because the developer who most needs it is the one least likely to
 * grant OAuth to a tool they have known for ninety seconds.
 */
export function ScanBox({ autoFocus = false }: { autoFocus?: boolean }) {
  const router = useRouter();
  const [value, setValue] = useState("");
  const [token, setToken] = useState("");
  const [showToken, setShowToken] = useState(false);
  const [confidential, setConfidential] = useState(false);
  const [creAvailable, setCreAvailable] = useState(false);

  useEffect(() => {
    let cancelled = false;
    fetch("/api/me")
      .then((r) => r.json())
      .then((me: { confidentialAvailable?: boolean }) => {
        if (!cancelled) setCreAvailable(Boolean(me.confidentialAvailable));
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    if (!value.trim()) return;
    const params = new URLSearchParams({ repo: value.trim() });
    if (confidential) params.set("mode", "confidential");
    // The token goes into sessionStorage, not the URL, so it never lands in
    // browser history, a referrer header, or a shared link.
    if (token.trim()) {
      try {
        sessionStorage.setItem("reposhield.token", token.trim());
      } catch {
        // Storage blocked; the scan proceeds without the pasted token.
      }
    }
    router.push(`/scan?${params}`);
  };

  return (
    <form onSubmit={submit} className="w-full">
      <div className="flex flex-col gap-2 sm:flex-row">
        <div className="relative flex-1">
          <Search
            size={15}
            className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[var(--color-faint)]"
          />
          <input
            className="input pl-9"
            placeholder="github.com/owner/repo"
            value={value}
            autoFocus={autoFocus}
            spellCheck={false}
            autoCapitalize="off"
            autoCorrect="off"
            onChange={(e) => setValue(e.target.value)}
            aria-label="GitHub repository URL"
          />
        </div>
        <button type="submit" className="btn btn-primary" disabled={!value.trim()}>
          Analyze
          <ArrowRight size={15} />
        </button>
      </div>

      {creAvailable ? (
        <label className="mt-3 flex cursor-pointer items-start gap-2.5">
          <input
            type="checkbox"
            checked={confidential}
            onChange={(e) => setConfidential(e.target.checked)}
            className="mt-0.5 size-3.5 accent-[var(--color-accent)]"
          />
          <span className="text-xs leading-relaxed text-[var(--color-muted)]">
            <span className="flex items-center gap-1.5 font-medium text-[var(--color-text)]">
              <ShieldCheck size={13} className="text-[var(--color-accent)]" />
              Analyse inside a Chainlink CRE enclave
            </span>
            Your repository is read and analysed inside a hardware-isolated TEE.
            This server never sees the source, and neither does the node
            operator — only a verdict comes back. You get a score without the
            file-by-file detail.
          </span>
        </label>
      ) : null}

      <div className="mt-2.5">
        {showToken ? (
          <div className="animate-fade-up">
            <input
              className="input"
              type="password"
              placeholder="ghp_… (classic token, repo scope)"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              aria-label="GitHub personal access token"
            />
            <p className="mt-1.5 text-xs leading-relaxed text-[var(--color-faint)]">
              Held in memory for this one scan and sent only to GitHub. It is
              never written to our server, our logs, or your browser history.
            </p>
          </div>
        ) : (
          <button
            type="button"
            onClick={() => setShowToken(true)}
            className="flex items-center gap-1.5 text-xs text-[var(--color-faint)] transition-colors hover:text-[var(--color-muted)]"
          >
            <KeyRound size={12} />
            Use your own token instead of signing in
          </button>
        )}
      </div>
    </form>
  );
}
