import Link from "next/link";
import { FileSearch, Lock, ShieldAlert, Sparkles, TerminalSquare } from "lucide-react";
import { ScanBox } from "@/components/scan-box";
import { SAMPLES } from "@/lib/samples";

export default function Home() {
  return (
    <div className="mx-auto max-w-6xl px-5 py-16 sm:py-24">
      <section className="max-w-3xl">
        <div className="inline-flex items-center gap-2 rounded-full border border-[var(--color-border-strong)] px-3 py-1 font-mono text-[0.68rem] uppercase tracking-[0.14em] text-[var(--color-muted)]">
          <ShieldAlert size={12} className="text-[var(--color-critical)]" />
          Contagious Interview · active campaign
        </div>

        <h1 className="mt-5 text-4xl font-semibold leading-[1.1] tracking-tight sm:text-5xl">
          Don&apos;t run code you were sent
          <br />
          by someone you just met.
        </h1>

        <p className="mt-5 max-w-xl text-base leading-relaxed text-[var(--color-muted)]">
          Fake recruiters send developers &ldquo;take-home assignments&rdquo; as GitHub
          repositories. Opening the folder or running <code className="font-mono text-sm text-[var(--color-text)]">npm install</code> is
          enough to hand over your SSH keys and your wallet. The repo looks
          completely normal when you read it.
        </p>

        <p className="mt-3 max-w-xl text-base leading-relaxed text-[var(--color-muted)]">
          Paste it here first. We read what it executes and tell you in plain
          English — no sign-in needed for public repos.
        </p>

        <div className="mt-8 max-w-2xl">
          <ScanBox autoFocus />
        </div>

        <div className="mt-6">
          <p className="font-mono text-[0.68rem] uppercase tracking-[0.16em] text-[var(--color-faint)]">
            Or see one that is actually malicious
          </p>
          <div className="mt-2.5 flex flex-wrap gap-2">
            {SAMPLES.map((sample) => (
              <Link
                key={sample.slug}
                href={`/scan?sample=${sample.slug}`}
                className="btn btn-ghost"
                title={sample.blurb}
              >
                <span
                  className="size-1.5 rounded-full"
                  style={{
                    background:
                      sample.expectedVerdict === "danger"
                        ? "var(--color-critical)"
                        : "var(--color-accent)",
                  }}
                />
                {sample.label}
              </Link>
            ))}
          </div>
        </div>
      </section>

      <section className="mt-24 grid gap-4 sm:grid-cols-3">
        <Card
          icon={<FileSearch size={16} />}
          title="Static filter first"
          body="31 rules read the manifests, editor config, CI, lockfiles and build scripts — the places that execute without you asking. Fast, free, and offline."
        />
        <Card
          icon={<Sparkles size={16} />}
          title="AI only where it matters"
          body="Files that trip a rule go to Gemini, which decodes the obfuscation and explains the execution flow. Nothing else does — that is what keeps it seconds, not minutes."
        />
        <Card
          icon={<TerminalSquare size={16} />}
          title="Commands, not lectures"
          body="Every report ends with what to type: how to clone without checking out, how to install without lifecycle scripts, what to delete before opening the folder."
        />
      </section>

      <section className="panel mt-6 flex flex-col gap-4 p-6 sm:flex-row sm:items-start">
        <Lock size={18} className="mt-0.5 shrink-0 text-[var(--color-accent)]" />
        <div>
          <h2 className="font-medium">Private repos, without trusting us</h2>
          <p className="mt-2 max-w-3xl text-sm leading-relaxed text-[var(--color-muted)]">
            Existing supply-chain scanners need to be installed by the repository
            <em> owner</em>. When a recruiter invites you to a private repo you only
            have read access, so none of them can help — you clone it blindly or walk
            away. RepoShield works from the candidate&apos;s side instead. Your GitHub
            token lives in an encrypted cookie in your own browser, is used to fetch
            files and then dropped, and signing out revokes the grant at GitHub.
            Reports are stored in your browser, never on our servers.
          </p>
          <Link
            href="/scan"
            className="mt-4 inline-flex items-center gap-1.5 text-sm text-[var(--color-accent)] hover:underline"
          >
            Scan a private repo →
          </Link>
        </div>
      </section>
    </div>
  );
}

function Card({
  icon,
  title,
  body,
}: {
  icon: React.ReactNode;
  title: string;
  body: string;
}) {
  return (
    <div className="panel p-5">
      <span className="flex size-8 items-center justify-center rounded-lg bg-[var(--color-surface-2)] text-[var(--color-accent)]">
        {icon}
      </span>
      <h3 className="mt-3 font-medium">{title}</h3>
      <p className="mt-1.5 text-sm leading-relaxed text-[var(--color-muted)]">{body}</p>
    </div>
  );
}
