"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import {
  AlertTriangle,
  ArrowRight,
  Check,
  ChevronDown,
  Cpu,
  Database,
  Eye,
  FileWarning,
  Fingerprint,
  Lock,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  X,
} from "lucide-react";
import { GithubMark } from "@/components/github-mark";
import { EnclaveDiagram, GraphLoopDiagram, PipelineDiagram } from "./diagrams";

/**
 * A full-screen, scroll-snapped presentation deck for /demo.
 *
 * Overlays the site chrome (fixed inset-0) so it presents clean. Arrow keys and
 * space page between slides; a rail shows position; each slide re-animates as it
 * becomes active. Designed for a ~3-minute narrated walk with a 1-minute live
 * buffer at the end.
 */

const SLIDES = [
  "title",
  "threat",
  "victims",
  "pain",
  "gap",
  "pipeline",
  "engine",
  "cre",
  "graph",
  "live",
  "close",
] as const;

export function Deck() {
  const [active, setActive] = useState(0);
  const go = (idx: number) => {
    setActive(Math.max(0, Math.min(SLIDES.length - 1, idx)));
  };

  // Transform-based deck: `active` moves a track via translateY. No scroll
  // container, so no snap/layout timing to fight. Wheel/trackpad steps slides.
  useEffect(() => {
    let cooldown = false;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      if (cooldown || Math.abs(e.deltaY) < 12) return;
      cooldown = true;
      setActive((a) => Math.max(0, Math.min(SLIDES.length - 1, a + (e.deltaY > 0 ? 1 : -1))));
      window.setTimeout(() => (cooldown = false), 600);
    };
    window.addEventListener("wheel", onWheel, { passive: false });
    return () => window.removeEventListener("wheel", onWheel);
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (["ArrowDown", "ArrowRight", " ", "PageDown", "Enter"].includes(e.key)) {
        e.preventDefault();
        go(active + 1);
      } else if (["ArrowUp", "ArrowLeft", "PageUp"].includes(e.key)) {
        e.preventDefault();
        go(active - 1);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [active]);

  return (
    <div
      className="fixed inset-0 z-50 h-screen w-screen overflow-hidden bg-[var(--color-bg)] text-[var(--color-text)]"
    >
      {/* progress rail */}
      <div className="fixed right-5 top-1/2 z-[60] hidden -translate-y-1/2 flex-col gap-2.5 sm:flex">
        {SLIDES.map((s, i) => (
          <button
            key={s}
            aria-label={`Slide ${i + 1}`}
            onClick={() => go(i)}
            className="size-2 rounded-full transition-all"
            style={{
              background: i === active ? "var(--color-accent)" : "var(--color-border-strong)",
              transform: i === active ? "scale(1.5)" : "scale(1)",
            }}
          />
        ))}
      </div>

      {/* exit + counter */}
      <div className="fixed left-5 top-4 z-[60] flex items-center gap-3">
        <Link
          href="/"
          className="flex items-center gap-1.5 rounded-full border border-[var(--color-border-strong)] bg-[var(--color-surface)]/70 px-3 py-1 font-mono text-[0.68rem] text-[var(--color-muted)] backdrop-blur transition-colors hover:text-[var(--color-text)]"
        >
          <ShieldCheck size={12} className="text-[var(--color-accent)]" /> RepoShield
        </Link>
        <span className="font-mono text-[0.68rem] text-[var(--color-faint)]">
          {String(active + 1).padStart(2, "0")} / {SLIDES.length}
        </span>
      </div>

      <div
        className="h-screen w-screen transition-transform duration-500 ease-out"
        style={{ transform: `translateY(-${active * 100}vh)` }}
      >
        {SLIDES.map((slide, i) => (
          <section
            key={slide}
            data-slide={i}
            data-active={active === i}
            className="deck-slide relative flex h-screen w-screen items-center justify-center px-6 sm:px-10"
          >
            <div className="deck-content w-full max-w-5xl">{renderSlide(slide, active === i)}</div>
            {i < SLIDES.length - 1 ? (
              <ChevronDown
                size={20}
                className="absolute bottom-6 left-1/2 -translate-x-1/2 animate-bounce text-[var(--color-faint)]"
              />
            ) : null}
          </section>
        ))}
      </div>

      <style>{`
        .deck-content { opacity: 0; transform: translateY(18px); transition: opacity .5s ease, transform .5s ease; }
        .deck-slide[data-active="true"] .deck-content { opacity: 1; transform: none; }
        .deck-stagger > * { opacity: 0; transform: translateY(12px); }
        .deck-slide[data-active="true"] .deck-stagger > * { animation: deck-in .5s ease forwards; }
        .deck-slide[data-active="true"] .deck-stagger > *:nth-child(1){animation-delay:.15s}
        .deck-slide[data-active="true"] .deck-stagger > *:nth-child(2){animation-delay:.28s}
        .deck-slide[data-active="true"] .deck-stagger > *:nth-child(3){animation-delay:.41s}
        .deck-slide[data-active="true"] .deck-stagger > *:nth-child(4){animation-delay:.54s}
        .deck-slide[data-active="true"] .deck-stagger > *:nth-child(5){animation-delay:.67s}
        .deck-slide[data-active="true"] .deck-stagger > *:nth-child(6){animation-delay:.80s}
        @keyframes deck-in { to { opacity: 1; transform: none; } }
        @media (prefers-reduced-motion: reduce) { .deck-content,.deck-stagger>*{opacity:1!important;transform:none!important;animation:none!important} }
      `}</style>
    </div>
  );
}

function Kicker({ children, color = "var(--color-accent)" }: { children: React.ReactNode; color?: string }) {
  return (
    <div
      className="mb-5 inline-flex items-center gap-2 rounded-full border px-3 py-1 font-mono text-[0.68rem] uppercase tracking-[0.16em]"
      style={{ borderColor: "var(--color-border-strong)", color }}
    >
      {children}
    </div>
  );
}

function renderSlide(slide: (typeof SLIDES)[number], activeNow: boolean) {
  switch (slide) {
    /* ── 1. Title ── */
    case "title":
      return (
        <div className="deck-stagger text-center">
          <div className="mx-auto mb-8 flex size-20 items-center justify-center rounded-3xl border border-[var(--color-accent-dim)] bg-[var(--color-accent-dim)]/30">
            <ShieldCheck size={40} className="text-[var(--color-accent)]" />
          </div>
          <h1 className="text-5xl font-semibold leading-tight tracking-tight sm:text-7xl">RepoShield</h1>
          <p className="mx-auto mt-5 max-w-2xl text-lg text-[var(--color-muted)] sm:text-2xl">
            Know what a repository does <em>before</em> you run it.
          </p>
          <p className="mt-8 font-mono text-xs text-[var(--color-faint)]">
            press → to begin · Chainlink CRE × The Graph
          </p>
        </div>
      );

    /* ── 2. The threat ── */
    case "threat":
      return (
        <div className="deck-stagger">
          <Kicker color="var(--color-critical)">
            <ShieldAlert size={12} /> The attack
          </Kicker>
          <h2 className="max-w-3xl text-4xl font-semibold leading-[1.1] tracking-tight sm:text-5xl">
            &ldquo;Great news — here&rsquo;s a quick take-home task.&rdquo;
          </h2>
          <p className="mt-6 max-w-2xl text-lg leading-relaxed text-[var(--color-muted)]">
            A recruiter DMs you a dream Web3 role. Step one: clone this repo, run{" "}
            <code className="font-mono text-[var(--color-text)]">npm install</code>, build the feature.
          </p>
          <div className="mt-10 grid gap-4 sm:grid-cols-3">
            {[
              ["Contagious Interview", "an active North-Korea-linked campaign (Lazarus)"],
              ["BeaverTail malware", "steals SSH keys, browser wallets, keychains"],
              ["5,600+ installs", "from typosquatted npm packages before takedown"],
            ].map(([h, s]) => (
              <div key={h} className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
                <p className="text-lg font-semibold" style={{ color: "var(--color-critical)" }}>
                  {h}
                </p>
                <p className="mt-1.5 text-sm text-[var(--color-muted)]">{s}</p>
              </div>
            ))}
          </div>
        </div>
      );

    /* ── 3. Real victims ── */
    case "victims":
      return (
        <div className="deck-stagger">
          <Kicker color="var(--color-critical)">
            <FileWarning size={12} /> Real people · real reports
          </Kicker>
          <h2 className="max-w-4xl text-4xl font-semibold leading-[1.1] tracking-tight sm:text-5xl">
            This isn&rsquo;t hypothetical.{" "}
            <span className="text-[var(--color-critical)]">One of these was sent to me.</span>
          </h2>
          <VictimStack />
          <p className="mt-6 max-w-3xl text-sm leading-relaxed text-[var(--color-muted)]">
            Engineers across LinkedIn describe the identical playbook: a legit-sounding recruiter, a
            &ldquo;quick take-home,&rdquo; then <em>&ldquo;just clone and run this GitHub repo.&rdquo;</em> The
            goal is always the same — run their code, drain your wallet, steal your keys.
          </p>
        </div>
      );

    /* ── 4. The pain ── */
    case "pain":
      return (
        <div className="deck-stagger">
          <Kicker color="var(--color-medium)">
            <Eye size={12} /> Why it works
          </Kicker>
          <h2 className="max-w-3xl text-4xl font-semibold leading-[1.1] tracking-tight sm:text-5xl">
            The repo looks normal. Opening it is the attack.
          </h2>
          <div className="mt-10 grid gap-6 sm:grid-cols-2">
            <div className="deck-stagger space-y-3">
              {[
                "A .vscode task runs the moment you open the folder",
                "A postinstall hook fires on npm install",
                "Payload hidden in an SVG, a test file, a base64 blob",
              ].map((t) => (
                <div key={t} className="flex items-start gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
                  <AlertTriangle size={18} className="mt-0.5 shrink-0 text-[var(--color-medium)]" />
                  <span className="text-sm text-[var(--color-muted)]">{t}</span>
                </div>
              ))}
            </div>
            <div className="flex flex-col justify-center rounded-xl border border-[var(--color-critical)]/40 bg-[var(--color-critical)]/5 p-6">
              <p className="text-2xl font-semibold leading-snug">
                You don&rsquo;t have the time, the expertise, or an isolated machine to check —
              </p>
              <p className="mt-3 text-lg text-[var(--color-muted)]">so you clone it blindly, or walk away from the job.</p>
            </div>
          </div>
        </div>
      );

    /* ── 5. The gap ── */
    case "gap":
      return (
        <div className="deck-stagger">
          <Kicker>
            <Lock size={12} /> The market gap
          </Kicker>
          <h2 className="max-w-3xl text-4xl font-semibold tracking-tight sm:text-5xl">
            Every existing scanner is built for the repo <span className="text-[var(--color-muted)]">owner</span>.
          </h2>
          <div className="mt-10 grid gap-5 sm:grid-cols-2">
            <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-6">
              <p className="font-mono text-xs uppercase tracking-widest text-[var(--color-faint)]">Socket · Snyk · Dependabot</p>
              <ul className="mt-4 space-y-2.5">
                {["Need a GitHub App or CI action installed", "You're an outside collaborator — read-only", "Can't touch a private interview repo"].map((t) => (
                  <li key={t} className="flex items-start gap-2.5 text-sm text-[var(--color-muted)]">
                    <X size={16} className="mt-0.5 shrink-0 text-[var(--color-critical)]" />
                    {t}
                  </li>
                ))}
              </ul>
            </div>
            <div className="rounded-xl border border-[var(--color-accent-dim)] bg-[var(--color-accent-dim)]/10 p-6">
              <p className="font-mono text-xs uppercase tracking-widest" style={{ color: "var(--color-accent)" }}>
                RepoShield · candidate-side
              </p>
              <ul className="mt-4 space-y-2.5">
                {["Paste a URL — nothing to install", "Reads a private repo you were invited to", "Tells you what it executes, in plain English"].map((t) => (
                  <li key={t} className="flex items-start gap-2.5 text-sm">
                    <Check size={16} className="mt-0.5 shrink-0 text-[var(--color-accent)]" />
                    {t}
                  </li>
                ))}
              </ul>
            </div>
          </div>
          <p className="mt-6 font-mono text-sm text-[var(--color-muted)]">→ the first scanner for the person being targeted.</p>
        </div>
      );

    /* ── 6. Pipeline ── */
    case "pipeline":
      return (
        <div className="deck-stagger">
          <Kicker>
            <Terminal size={12} /> How it works
          </Kicker>
          <h2 className="text-4xl font-semibold tracking-tight sm:text-5xl">Two phases. Fast, cheap, thorough.</h2>
          <div className="mt-8 rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-6">{activeNow ? <PipelineDiagram /> : <div className="h-[260px]" />}</div>
          <div className="mt-6 grid gap-4 sm:grid-cols-3 text-sm">
            <p className="text-[var(--color-muted)]"><strong className="text-[var(--color-text)]">38 static rules</strong> find the risky files — offline, free.</p>
            <p className="text-[var(--color-muted)]"><strong className="text-[var(--color-text)]">Gemini</strong> reads only those, and explains what they do.</p>
            <p className="text-[var(--color-muted)]"><strong className="text-[var(--color-text)]">The Graph</strong> adds what the community already knows.</p>
          </div>
        </div>
      );

    /* ── 7. Engine ── */
    case "engine":
      return (
        <div className="deck-stagger">
          <Kicker>
            <Fingerprint size={12} /> Precision
          </Kicker>
          <h2 className="max-w-3xl text-4xl font-semibold leading-[1.1] tracking-tight sm:text-5xl">
            It judges a file by what it <em>can</em> do.
          </h2>
          <div className="mt-8 grid items-center gap-6 sm:grid-cols-2">
            <div className="deck-stagger space-y-3">
              {[
                ["Solidity can't touch your disk", "so host-threat rules never fire on .sol"],
                ["node_modules & forge-std are noticed", "vendored code is down-weighted, not screamed at"],
                ["Entropy, XOR, typosquats, BeaverTail TTPs", "novel obfuscation caught by shape, not signature"],
              ].map(([h, s]) => (
                <div key={h} className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
                  <p className="text-sm font-semibold">{h}</p>
                  <p className="mt-1 text-sm text-[var(--color-muted)]">{s}</p>
                </div>
              ))}
            </div>
            <div className="flex items-center justify-center gap-6">
              <ScoreBadge score={100} label="fake interview repo" color="var(--color-critical)" />
              <ScoreBadge score={0} label="real Foundry project" color="var(--color-accent)" />
            </div>
          </div>
          <p className="mt-6 font-mono text-xs text-[var(--color-faint)]">
            backtested on 11 real repos (express, vite, ethers, OpenZeppelin…) → all &ldquo;safe&rdquo;.
          </p>
        </div>
      );

    /* ── 8. Chainlink CRE ── */
    case "cre":
      return (
        <div className="deck-stagger">
          <Kicker color="#4ade9b">
            <Cpu size={12} /> Chainlink CRE · Confidential Workflows
          </Kicker>
          <h2 className="max-w-3xl text-4xl font-semibold leading-[1.1] tracking-tight sm:text-5xl">
            Scan a private repo without trusting us with it.
          </h2>
          <p className="mt-4 max-w-2xl text-[var(--color-muted)]">
            Reading a private repo needs a token that reads <em>all</em> your repos. So the whole analysis
            runs inside a hardware enclave — our servers and the node operator never see your token or code.
          </p>
          <div className="mt-6 rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-6">{activeNow ? <EnclaveDiagram /> : <div className="h-[340px]" />}</div>
        </div>
      );

    /* ── 9. The Graph ── */
    case "graph":
      return (
        <div className="deck-stagger">
          <Kicker color="#c4a3ff">
            <Database size={12} /> The Graph · onchain registry
          </Kicker>
          <h2 className="max-w-3xl text-4xl font-semibold leading-[1.1] tracking-tight sm:text-5xl">
            What one scan can&rsquo;t know: what everyone else found.
          </h2>
          <div className="mt-6 rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-6">{activeNow ? <GraphLoopDiagram /> : <div className="h-[300px]" />}</div>
          <p className="mt-5 max-w-3xl text-sm text-[var(--color-muted)]">
            Verdicts are published to a <strong className="text-[var(--color-text)]">Sepolia contract</strong>, indexed by a{" "}
            <strong className="text-[var(--color-text)]">subgraph</strong>, and the{" "}
            <strong className="text-[var(--color-text)]">LLM reads it back</strong> — so a repo whose owner has a
            pattern of flagged repos is caught before its code is even read.
          </p>
        </div>
      );

    /* ── 10. Live demo cue ── */
    case "live":
      return (
        <div className="deck-stagger text-center">
          <div className="mx-auto mb-8 flex size-20 items-center justify-center rounded-3xl border border-[var(--color-accent-dim)] bg-[var(--color-accent-dim)]/30">
            <ArrowRight size={40} className="text-[var(--color-accent)]" />
          </div>
          <p className="font-mono text-xs uppercase tracking-[0.2em] text-[var(--color-faint)]">Live</p>
          <h2 className="mt-4 text-4xl font-semibold tracking-tight sm:text-6xl">Let me show you.</h2>
          <p className="mx-auto mt-6 max-w-xl text-lg text-[var(--color-muted)]">
            Scanning a real private &ldquo;interview&rdquo; repo — and watching a verdict land onchain.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link href="/scan" className="btn btn-primary">
              <GithubMark /> Open the scanner
            </Link>
            <Link href="/registry" className="btn btn-ghost">
              <Database size={15} /> The registry
            </Link>
          </div>
        </div>
      );

    /* ── 11. Close ── */
    case "close":
      return (
        <div className="deck-stagger text-center">
          <ShieldCheck size={44} className="mx-auto text-[var(--color-accent)]" />
          <h2 className="mt-6 text-4xl font-semibold tracking-tight sm:text-6xl">RepoShield</h2>
          <p className="mx-auto mt-5 max-w-2xl text-lg text-[var(--color-muted)]">
            The first candidate-side scanner for the Contagious Interview attack — private-safe with{" "}
            <span className="text-[var(--color-text)]">Chainlink CRE</span>, community-powered by{" "}
            <span className="text-[var(--color-text)]">The Graph</span>.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-x-6 gap-y-2 font-mono text-xs text-[var(--color-faint)]">
            <span>repo-shield.vercel.app</span>
            <span className="flex items-center gap-1.5"><Cpu size={12} /> CRE simulated</span>
            <span className="flex items-center gap-1.5"><Database size={12} /> live on Sepolia</span>
          </div>
          <p className="mt-10 text-sm text-[var(--color-muted)]">Thank you.</p>
        </div>
      );
  }
}

function VictimStack() {
  // The screenshots are real LinkedIn scam-warning posts, blurred so no
  // individual is identifiable — the point is the *volume* of identical
  // reports, not any one person's words. Fanned like a pile of evidence.
  const cards = [1, 2, 3, 4, 5];
  const mid = (cards.length - 1) / 2;
  return (
    <div className="relative mx-auto mt-10 flex h-[300px] w-full max-w-3xl items-center justify-center sm:h-[340px]">
      {cards.map((n, i) => {
        const offset = i - mid; // -2 … +2
        return (
          <div
            key={n}
            className="absolute h-[260px] w-[200px] overflow-hidden rounded-xl border border-[var(--color-border-strong)] bg-[var(--color-surface)] shadow-2xl transition-transform duration-500 sm:h-[300px] sm:w-[230px]"
            style={{
              transform: `translateX(${offset * 130}px) rotate(${offset * 7}deg) translateY(${Math.abs(offset) * 14}px)`,
              zIndex: cards.length - Math.abs(offset),
            }}
          >
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img
              src={`/photos/victim-${n}.png`}
              alt="A real, blurred fake-interview scam warning post"
              className="absolute inset-0 size-full object-cover object-top"
            />
            <span className="pointer-events-none absolute inset-0 rounded-xl ring-1 ring-inset ring-white/5" />
          </div>
        );
      })}
      <div className="pointer-events-none absolute -bottom-2 left-1/2 -translate-x-1/2 rounded-full border border-[var(--color-border-strong)] bg-[var(--color-bg)] px-3 py-1 font-mono text-[0.6rem] text-[var(--color-muted)]">
        real LinkedIn posts · blurred
      </div>
    </div>
  );
}

function ScoreBadge({ score, label, color }: { score: number; label: string; color: string }) {
  return (
    <div className="text-center">
      <div
        className="flex size-28 items-center justify-center rounded-full border-4 font-mono text-4xl font-bold"
        style={{ borderColor: color, color }}
      >
        {score}
      </div>
      <p className="mt-2 max-w-[7rem] text-xs text-[var(--color-muted)]">{label}</p>
    </div>
  );
}
