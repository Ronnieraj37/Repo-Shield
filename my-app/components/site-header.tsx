"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { Cpu, Database, History, LogOut, Shield } from "lucide-react";

interface Me {
  user: { login: string; name: string | null; avatarUrl: string } | null;
  signInAvailable: boolean;
}

export function SiteHeader() {
  const pathname = usePathname();
  const hidden = pathname === "/idea";
  const [me, setMe] = useState<Me | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch("/api/me")
      .then((r) => r.json())
      .then((data: Me) => {
        if (!cancelled) setMe(data);
      })
      .catch(() => {
        if (!cancelled) setMe({ user: null, signInAvailable: false });
      });
    return () => {
      cancelled = true;
    };
  }, [pathname]);

  if (hidden) return null;

  return (
    <header className="relative z-10 border-b border-[var(--color-border)]">
      <div className="mx-auto flex h-14 max-w-6xl items-center gap-4 px-5">
        <Link href="/" className="flex items-center gap-2 font-semibold tracking-tight">
          <Shield size={17} className="text-[var(--color-accent)]" />
          RepoShield
        </Link>

        <nav className="ml-auto flex items-center gap-1 text-sm">
          <Link
            href="/scan"
            className={`rounded px-2.5 py-1.5 transition-colors hover:text-[var(--color-text)] ${
              pathname === "/scan" ? "text-[var(--color-text)]" : "text-[var(--color-muted)]"
            }`}
          >
            Scan
          </Link>
          <Link
            href="/confidential"
            className={`flex items-center gap-1.5 rounded px-2.5 py-1.5 transition-colors hover:text-[var(--color-text)] ${
              pathname === "/confidential"
                ? "text-[var(--color-text)]"
                : "text-[var(--color-muted)]"
            }`}
          >
            <Cpu size={14} />
            Confidential
          </Link>
          <Link
            href="/registry"
            className={`flex items-center gap-1.5 rounded px-2.5 py-1.5 transition-colors hover:text-[var(--color-text)] ${
              pathname === "/registry" ? "text-[var(--color-text)]" : "text-[var(--color-muted)]"
            }`}
          >
            <Database size={14} />
            Registry
          </Link>
          <Link
            href="/history"
            className={`flex items-center gap-1.5 rounded px-2.5 py-1.5 transition-colors hover:text-[var(--color-text)] ${
              pathname === "/history" ? "text-[var(--color-text)]" : "text-[var(--color-muted)]"
            }`}
          >
            <History size={14} />
            History
          </Link>

          {me?.user ? (
            <div className="ml-2 flex items-center gap-2 border-l border-[var(--color-border)] pl-3">
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img
                src={me.user.avatarUrl}
                alt=""
                className="size-6 rounded-full border border-[var(--color-border-strong)]"
              />
              <span className="font-mono text-xs text-[var(--color-muted)]">
                {me.user.login}
              </span>
              <button
                type="button"
                title="Sign out and revoke this app's GitHub access"
                className="rounded p-1.5 text-[var(--color-faint)] transition-colors hover:text-[var(--color-critical)]"
                onClick={async () => {
                  await fetch("/api/auth/logout", { method: "POST" });
                  window.location.reload();
                }}
              >
                <LogOut size={14} />
              </button>
            </div>
          ) : null}
        </nav>
      </div>
    </header>
  );
}
