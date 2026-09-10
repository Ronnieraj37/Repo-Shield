"use client";

import { usePathname } from "next/navigation";

export function SiteFooter() {
  // The /idea deck is a full-screen presentation; site chrome would break it.
  if (usePathname() === "/idea") return null;
  return (
    <footer className="relative z-10 border-t border-[var(--color-border)] py-5">
      <div className="mx-auto max-w-6xl px-5 text-xs text-[var(--color-faint)]">
        Scan results are stored in your browser and never sent to our servers.
        RepoShield reports evidence about what a repository contains — it cannot
        prove that code is safe.
      </div>
    </footer>
  );
}
