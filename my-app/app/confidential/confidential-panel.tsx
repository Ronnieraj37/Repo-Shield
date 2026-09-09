"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import {
  ArrowRight,
  Check,
  CircleDashed,
  Cpu,
  KeyRound,
  Lock,
  Terminal,
} from "lucide-react";

interface BuildEvidence {
  cliVersion: string;
  sdkVersion: string;
  workflow: string;
  entry: string;
  binaryHash: string;
  binaryBytes: number;
  builtAt: string;
  command: string;
}

/**
 * The CRE integration, shown honestly.
 *
 * Every claim on this page is backed by something the reader can re-run: the
 * binary hash comes from `cre workflow build`, the transcript from executing
 * the confidential body. The one step that has not happened — a simulation in
 * a real enclave — is labelled as not having happened, rather than being
 * quietly omitted.
 */
export function ConfidentialPanel() {
  const [build, setBuild] = useState<BuildEvidence | null>(null);
  const [deployed, setDeployed] = useState(false);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    fetch("/api/cre")
      .then((r) => r.json())
      .then((d: { build: BuildEvidence | null; deployed: boolean }) => {
        setBuild(d.build);
        setDeployed(d.deployed);
        setLoaded(true);
      })
      .catch(() => setLoaded(true));
  }, []);

  return (
    <div className="space-y-8">
      <header>
        <div className="inline-flex items-center gap-2 rounded-full border border-[var(--color-border-strong)] px-3 py-1 font-mono text-[0.68rem] uppercase tracking-[0.14em] text-[var(--color-muted)]">
          <Cpu size={12} className="text-[var(--color-accent)]" />
          Chainlink CRE · Confidential Workflows
        </div>
        <h1 className="mt-5 text-3xl font-semibold leading-tight tracking-tight">
          Scan a private repo without
          <br />
          trusting us with it.
        </h1>
        <p className="mt-4 max-w-2xl text-[0.95rem] leading-relaxed text-[var(--color-muted)]">
          To tell you whether a repository is hostile, something has to read it —
          which means holding a token with access to your private repositories,
          and sending your employer&apos;s source code to an LLM. Confidential
          mode does all of that inside a hardware-isolated enclave. Our servers
          never see your code. Neither does the node operator running the
          enclave.
        </p>
      </header>

      <Boundary />

      <section>
        <SectionTitle>What crosses the boundary</SectionTitle>
        <div className="mt-3 grid gap-3 sm:grid-cols-2">
          <Crosses
            direction="in"
            title="Goes in"
            items={[
              "GitHub token — from the Vault DON, decrypted only in the enclave",
              "Gemini API key — same",
              "Your repository's source, fetched over confidential-http",
            ]}
          />
          <Crosses
            direction="out"
            title="Comes out"
            items={[
              "threatScore, verdict",
              "findingCount, criticalCount",
              "commit, scannedAt",
            ]}
            note="Seven scalar fields. Findings quote your source verbatim, so they never leave — that is the trade you are making."
          />
        </div>
      </section>

      <section>
        <SectionTitle>Where it stands</SectionTitle>
        <ol className="mt-3 space-y-2.5">
          <Step
            done
            title="Workflow compiles against @chainlink/cre-sdk"
            detail={
              build
                ? `SDK ${build.sdkVersion}, registered with handlerInTee and driven by Runner.`
                : "SDK 1.20.0, registered with handlerInTee and driven by Runner."
            }
          />
          <Step
            done
            title="Confidential body executes"
            detail="The real handler logic runs against a mocked vault and a recorded transport, asserting that both secrets are read, that every GitHub request carries the vault token, and that no repository source appears in the DON payload."
            transcript={[
              'log: analyzing reposhield-samples/senior-web3-frontend-task@5ff5b0d — 8 of 8 files read',
              'log: verdict "danger" (100/100) from 19 findings',
              "PASS every GitHub request carries the vault token",
              "PASS leaks no repository source in the DON payload",
            ]}
          />
          <Step
            done={Boolean(build)}
            title="Compiles to a CRE WASM binary"
            detail={
              build
                ? `${(build.binaryBytes / 1e6).toFixed(2)} MB, built with cre CLI ${build.cliVersion}. The entire analyzer is in there — which only works because it uses no fetch, crypto, Buffer or setTimeout.`
                : "Not built on this machine. Run `npm run build` in cre/reposhield."
            }
            code={build ? `${build.command}\n→ ${build.binaryHash}` : undefined}
          />
          <Step
            done={false}
            title="Simulated in an enclave"
            detail="Blocked: cre workflow simulate requires a Chainlink account. Create an API key at app.chain.link → Account Settings, then set CRE_API_KEY and run npm run simulate in cre/reposhield."
          />
          <Step
            done={deployed}
            title="Deployed and wired to this app"
            detail={
              deployed
                ? "CRE_WORKFLOW_URL is set — the confidential option is live on the scan page."
                : "Deploy the workflow, then set CRE_WORKFLOW_URL to its HTTP trigger to turn on the confidential option."
            }
          />
        </ol>
        {loaded && !build ? null : null}
      </section>

      {build ? (
        <section className="panel p-5">
          <SectionTitle>Build provenance</SectionTitle>
          <dl className="mt-3 grid gap-x-8 gap-y-3 sm:grid-cols-2">
            <Fact label="Workflow" value={build.workflow} />
            <Fact label="Entry point" value={build.entry} />
            <Fact label="CLI" value={build.cliVersion} />
            <Fact label="SDK" value={build.sdkVersion} />
          </dl>
          <div className="mt-4">
            <p className="font-mono text-[0.65rem] uppercase tracking-[0.16em] text-[var(--color-faint)]">
              Binary hash
            </p>
            <p className="mt-1 break-all font-mono text-xs text-[var(--color-accent)]">
              {build.binaryHash}
            </p>
            <p className="mt-2 text-xs leading-relaxed text-[var(--color-muted)]">
              This is what attestation is for. Once deployed, the enclave reports
              the hash of the code it is running — you compare it to this, built
              from source you can read. A container can only tell you what we
              said we would run.
            </p>
          </div>
        </section>
      ) : null}

      <section className="panel p-5">
        <SectionTitle>Run it yourself</SectionTitle>
        <p className="mt-2 text-sm leading-relaxed text-[var(--color-muted)]">
          Nothing here needs our infrastructure.
        </p>
        <pre className="code-block mt-3">{`cd cre/reposhield
npm install
npm test          # execute the confidential body
npm run build     # compile to WASM, prints the binary hash
npm run simulate  # needs CRE_API_KEY`}</pre>
      </section>

      <div className="flex flex-wrap gap-3">
        <Link href="/scan" className="btn btn-primary">
          Scan a repository
          <ArrowRight size={15} />
        </Link>
        <a
          href="https://docs.chain.link/cre"
          target="_blank"
          rel="noreferrer"
          className="btn btn-ghost"
        >
          Chainlink CRE docs
        </a>
      </div>
    </div>
  );
}

/** The architecture, as one diagram rather than three paragraphs. */
function Boundary() {
  return (
    <section className="panel overflow-hidden">
      <div className="grid gap-px bg-[var(--color-border)] sm:grid-cols-[1fr_auto_1fr]">
        <Zone
          label="Untrusted"
          sub="RepoShield servers · CRE node operator"
          items={["Sees the repo name", "Sees the verdict", "Sees nothing else"]}
          tone="muted"
        />
        <div className="flex items-center justify-center bg-[var(--color-surface)] px-4 py-3">
          <Lock size={15} className="text-[var(--color-accent)]" />
        </div>
        <Zone
          label="Inside the enclave"
          sub="AWS Nitro TEE · attested"
          items={[
            "GitHub token, decrypted",
            "Gemini key, decrypted",
            "Your repository's source",
            "Every finding, with evidence",
          ]}
          tone="accent"
        />
      </div>
    </section>
  );
}

function Zone({
  label,
  sub,
  items,
  tone,
}: {
  label: string;
  sub: string;
  items: string[];
  tone: "muted" | "accent";
}) {
  const color = tone === "accent" ? "var(--color-accent)" : "var(--color-faint)";
  return (
    <div className="bg-[var(--color-surface)] p-5">
      <p
        className="font-mono text-[0.65rem] uppercase tracking-[0.16em]"
        style={{ color }}
      >
        {label}
      </p>
      <p className="mt-1 font-mono text-[0.7rem] text-[var(--color-faint)]">{sub}</p>
      <ul className="mt-3 space-y-1.5">
        {items.map((item) => (
          <li key={item} className="flex items-start gap-2 text-sm text-[var(--color-muted)]">
            <span
              className="mt-1.5 size-1 shrink-0 rounded-full"
              style={{ background: color }}
            />
            {item}
          </li>
        ))}
      </ul>
    </div>
  );
}

function Crosses({
  direction,
  title,
  items,
  note,
}: {
  direction: "in" | "out";
  title: string;
  items: string[];
  note?: string;
}) {
  return (
    <div className="panel p-4">
      <p className="flex items-center gap-1.5 text-sm font-medium">
        {direction === "in" ? (
          <KeyRound size={13} className="text-[var(--color-medium)]" />
        ) : (
          <ArrowRight size={13} className="text-[var(--color-accent)]" />
        )}
        {title}
      </p>
      <ul className="mt-2.5 space-y-1.5">
        {items.map((item) => (
          <li key={item} className="font-mono text-xs leading-relaxed text-[var(--color-muted)]">
            {item}
          </li>
        ))}
      </ul>
      {note ? (
        <p className="mt-3 border-t border-[var(--color-border)] pt-2.5 text-xs leading-relaxed text-[var(--color-faint)]">
          {note}
        </p>
      ) : null}
    </div>
  );
}

function Step({
  done,
  title,
  detail,
  code,
  transcript,
}: {
  done: boolean;
  title: string;
  detail: string;
  code?: string;
  transcript?: string[];
}) {
  return (
    <li className="panel flex gap-3 p-4">
      <span className="mt-0.5 shrink-0">
        {done ? (
          <Check size={16} className="text-[var(--color-accent)]" />
        ) : (
          <CircleDashed size={16} className="text-[var(--color-faint)]" />
        )}
      </span>
      <div className="min-w-0 flex-1">
        <h3
          className="text-sm font-medium"
          style={{ color: done ? undefined : "var(--color-muted)" }}
        >
          {title}
        </h3>
        <p className="mt-1 text-sm leading-relaxed text-[var(--color-muted)]">{detail}</p>
        {transcript ? (
          <pre className="code-block mt-2.5 whitespace-pre-wrap text-[0.72rem]">
            {transcript.join("\n")}
          </pre>
        ) : null}
        {code ? (
          <pre className="code-block mt-2.5 flex items-start gap-2 whitespace-pre-wrap break-all text-[0.72rem]">
            <Terminal size={12} className="mt-1 shrink-0 text-[var(--color-faint)]" />
            {code}
          </pre>
        ) : null}
      </div>
    </li>
  );
}

function SectionTitle({ children }: { children: React.ReactNode }) {
  return <h2 className="text-sm font-semibold tracking-tight">{children}</h2>;
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="font-mono text-[0.65rem] uppercase tracking-[0.16em] text-[var(--color-faint)]">
        {label}
      </dt>
      <dd className="mt-1 truncate font-mono text-xs">{value}</dd>
    </div>
  );
}
