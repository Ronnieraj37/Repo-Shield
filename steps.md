# 🛡️ RepoShield — Implementation Steps

> **One line:** Paste an unfamiliar GitHub repo. Find out what it does when you run it — before you run it.

---

## Status — 9 Sep 2026

| Piece | State |
|---|---|
| Analyzer (38 rules) | ✅ Working. `yarn test:analyzer` — 4 fixtures, all green, 17 false-positive assertions |
| Large-repo strategy | ✅ Risk-ranked selection. 50k-file monorepo → 0.22% coverage, all high-risk files still caught; coverage disclosed in the report |
| Phase 2 (Gemini) | ✅ Working live. ~12s for 6 flagged files. Races two models; fails open |
| Web app (landing/scan/report/history) | ✅ Working. SSE progress, local-first storage |
| Anonymous scanning | ✅ Working. Verified against `expressjs/express`, `sindresorhus/execa` |
| Sessions | ✅ 30-day rolling. Not exercised end-to-end — needs an OAuth app (see below) |
| GitHub OAuth sign-in | ⚠️ Code complete, **unconfigured**. Needs `GITHUB_CLIENT_ID`/`SECRET` |
| CRE workflow | ✅ Compiles to a **WASM binary** via `cre` CLI v1.33.0 (hash `960be3ac…`), executes under test, wired into the app as "Confidential scan", surfaced at `/confidential`. Simulation blocked on `CRE_API_KEY` |
| Rate limit | ⚠️ Anonymous budget exhausts after ~5 scans/hour. Needs `GITHUB_TOKEN` |

### Blocked on a human

1. **Create a GitHub OAuth App** → `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`.
   Callback: `http://localhost:3000/api/auth/github/callback`.
   Without this the private-repo path cannot be tested at all.
2. **Create a classic PAT with no scopes** → `GITHUB_TOKEN`. Raises the
   anonymous limit from 60/hr to 5,000/hr. Close to mandatory for a demo.
3. **Create a `CRE_API_KEY`** at app.chain.link → Account Settings. The CLI is
   installed and `cre workflow build` already works offline; `simulate` and
   `deploy` are the only steps that need the account. Then register
   `GEMINI_API_KEY` and `GITHUB_TOKEN` in the Vault DON, run
   `cre workflow simulate .`, then deploy and set `CRE_WORKFLOW_URL` in the web
   app's env — that env var is what turns on the "Confidential scan" toggle.

### What testing changed

Calibrating against 88 real dependency names and two live repositories found
four defects that fixture-only testing would never have surfaced:

- a **dedup bug** collapsing multi-finding rules onto one key (`rule:file:line`
  with no line number), silently dropping findings
- **R09** flagging `xo` as a typo of `zod` — now length-scaled, scope-aware, and
  using Damerau-Levenshtein so transpositions (the commonest squat) count as one
  edit
- **R05** firing on any base64 decode — now requires proximity to an execution
  or network sink
- **R11** flagging scoped private registries, which are how every company with
  internal packages is configured — now only the global registry is high severity

## 0 — Decisions Log

These differ from the first draft of this document. Reasons included so we don't re-litigate them.

| Decision | Choice | Why |
|---|---|---|
| Repo layout | **Single Next.js app** (`my-app/`), not a monorepo | The analyzer is a pure function in `lib/analyzer`. Both the Next route handler and the CRE workflow import the *same* code. A workspace adds build friction and buys nothing at this size. |
| Styling | **Tailwind v4** (already installed) + CSS custom properties | It's already wired up via `@tailwindcss/postcss`. Vanilla CSS was the earlier call; overridden to avoid rewriting working config. Theme tokens still live in `@theme` so the palette is swappable. |
| Auth | **Hand-rolled GitHub OAuth**, no NextAuth | NextAuth v4 is not Next 16 compatible and v5 is beta. More importantly: the token lifecycle *is* our product story ("your token never rests on our disk"). Hiding it inside a library we can't narrate is a loss, not a win. ~120 lines. |
| Session storage | **AES-256-GCM encrypted httpOnly cookie**, 1h TTL, no server DB | Nothing to breach. The cookie is opaque to the client; the token is decrypted per-request, used, and dropped. |
| Report storage | **`localStorage`, client-side only** | Findings about someone's private repo must not accumulate on our server. Local-first is the honest implementation of the privacy claim, and it removes the DB from the build entirely. |
| AI model | **Gemini**, two models raced in parallel | `gemini-2.5-flash` was retired for new API keys mid-build. Benchmarking found the flagship `flash` models 503-ing 1–2 times in 3 while `lite` models answered 3/3, so a strong model and a reliable one are raced and the first answer wins. Only flagged files reach either. |
| CRE usage | **`handlerInTee`** + confidential-http | Chainlink "Best Confidential Workflow" track. Secrets are `getSecret()`-ed inside the enclave and every outbound call goes through the confidential-http capability. |
| Analyzer portability | **No `fetch`, `crypto`, `Buffer` or `setTimeout` in the engine** | The CRE WASM runtime types all four as `never`. The engine takes an injected `HttpClient` and uses hand-written SHA-256/base64/UTF-8, so one copy of the code runs in Node and in the enclave. This is what makes "the same analyzer" true rather than aspirational. |

---

## 1 — The Access Problem (read this before building auth)

This is the single most important design constraint in the project, and the first draft glossed it.

**The scenario:** a fake recruiter invites the developer to a private repo as an *outside collaborator*. The developer has read access. That is all.

**What that rules out:**

| Method | Works on a repo you're an outside collaborator on? | Why |
|---|---|---|
| GitHub App installation | ❌ | You can only install an App on repos in an account you admin. You don't admin the recruiter's account. |
| Fine-grained PAT | ❌ | Fine-grained PATs can only access resources **owned by the token's owner**. The repo isn't yours. |
| Classic PAT (`repo` scope) | ✅ | Full read/write on every private repo you can touch. |
| OAuth App (`repo` scope) | ✅ | Same grant, but revocable by us and never typed into a form. |

So the two things that *work* are also the two broadest grants GitHub offers. There is no read-only option. Pretending otherwise would be dishonest, so we design around it:

**Tier 1 — Anonymous (default, zero friction).**
No sign-in. Public repos only, via unauthenticated GitHub API (60 req/hr/IP — we use ~5, and the server may hold an optional `GITHUB_TOKEN` to raise the ceiling). Most scans should land here. **Do not put a sign-in wall in front of the landing page.**

**Tier 2 — GitHub OAuth (only prompted when needed).**
Triggered when a repo returns 404/403 anonymously → "This repo is private. Sign in to scan it." Scope: `read:user repo`. The consent screen says exactly what that grants, in our own words, above the button. On sign-out we call `DELETE /applications/{client_id}/grant` so the grant is actually gone from their GitHub account, not just our cookie.

**Tier 3 — Paste a token (escape hatch).**
For developers who won't grant OAuth to a tool they just met — a completely reasonable stance for a security product. They paste a classic PAT, it's held in memory for that one request, never stored, never logged. Ship this: it costs one input field and it's the most trust-building feature in the app.

- [ ] **1.1** `lib/session.ts` — AES-256-GCM seal/unseal, `SESSION_SECRET` from env
- [ ] **1.2** `GET /api/auth/github` — state cookie + redirect to GitHub authorize
- [ ] **1.3** `GET /api/auth/github/callback` — state check, code→token exchange, seal into cookie
- [ ] **1.4** `POST /api/auth/logout` — revoke grant at GitHub, then clear cookie
- [ ] **1.5** `GET /api/me` — current user (login, avatar, rate-limit budget) or `null`
- [ ] **1.6** Token resolution order per request: pasted PAT → session cookie → server `GITHUB_TOKEN` → anonymous

---

## 2 — Analyzer (`lib/analyzer/`)

The heart. Pure, dependency-light, no I/O — takes a file tree + file contents, returns a report. Runs identically in the Next route and inside the TEE.

```
lib/analyzer/
├── types.ts        # shared interfaces
├── detector.ts     # project type + which files to fetch
├── parser.ts       # config file parsers
├── rules.ts        # Phase 1: heuristics
├── gemini.ts       # Phase 2: AI on flagged files only
├── scorer.ts       # score + verdict aggregation
├── remediation.ts  # "what do I do now" action plan
└── index.ts        # analyzeRepo() orchestrator
```

### 2.1 Types

```ts
type FrameworkType = "foundry" | "hardhat" | "truffle" | "anchor" | "cargo"
                   | "go" | "nodejs" | "python" | "deno" | "bun" | "unknown";
type Severity = "critical" | "high" | "medium" | "low" | "info";
type Verdict  = "safe" | "caution" | "danger";
type Phase    = "static" | "ai";

interface Finding {
  id: string; ruleId: string; severity: Severity; phase: Phase;
  category: string; title: string; description: string;
  file: string; line?: number; evidence: string; recommendation: string;
  aiExplanation?: string; confirmedByAI?: boolean;
}

interface ThreatReport {
  id: string;                 // sha256(repo + commit).slice(0,16) — addressable & dedupable
  repo: { owner, name, url, ref, commit, private, stars, pushedAt };
  timestamp: string;
  profile: ProjectProfile;
  threatScore: number;        // 0-100
  verdict: Verdict;
  findings: Finding[];
  summary: string;
  actionPlan: ActionStep[];
  stats: { filesInTree, filesFetched, filesFlagged, filesAnalyzedByAI, durationMs };
  degraded?: string[];        // e.g. "AI phase skipped: no API key"
}
```

### 2.2 Detector

Framework fingerprints (`foundry.toml`, `hardhat.config.*`, `Cargo.toml`, `go.mod`, `package.json`, `pyproject.toml`, `deno.json`, `bun.lockb`, `Anchor.toml`, …) **plus** the always-fetch list — files that are dangerous regardless of project type:

`.vscode/tasks.json`, `.vscode/launch.json`, `.vscode/settings.json`, `.idea/**`, `.npmrc`, `.yarnrc.yml`, `.yarn/plugins/**`, `setup.py`, `conftest.py`, `sitecustomize.py`, `build.rs`, `Makefile`, `justfile`, `Dockerfile`, `docker-compose.yml`, `.github/workflows/*`, `.devcontainer/**`, root `*.sh|*.bash|*.ps1|*.bat|*.cmd`, all `*.svg`, and any file the tree reports as suspiciously large-for-its-type.

Budget guard: cap at **60 files / 1.5 MB total**, prioritized by risk. Repos are unbounded; our costs are not.

### 2.3 Rules (Phase 1)

Everything from the first draft, plus the vectors it missed. Marked ✨ = new.

| # | Rule | Sev | Vector |
|---|---|---|---|
| R01 | `pre/postinstall` with `curl\|bash`, `wget\|sh` | 🔴 | Payload dropper |
| R02 | `pre/postinstall` with `node -e` + base64/hex | 🔴 | Obfuscated exec |
| R03 | `eval()` / `new Function()` in scripts or config | 🔴 | Dynamic exec |
| R04 | `child_process` in a config or non-tool file | 🔴 | Shell spawn |
| R05 | `Buffer.from(…,'base64')` / `atob()` in scripts | 🟡 | Encoded payload |
| R06 | `.vscode/tasks.json` with `runOptions.runOn: "folderOpen"` ✨ | 🔴 | **Auto-executes on folder open — the actual trigger, not merely the presence of a `command`** |
| R07 | `ffi = true` in `foundry.toml` | 🟡 | Shell from Solidity |
| R08 | `build.rs` / `[build-dependencies]` | 🟡 | Compile-time exec |
| R09 | Dependency ≤2 Levenshtein from a popular package | 🟡 | Typosquat |
| R10 | Unpinned versions / no lockfile | 🟠 | Supply chain |
| R11 | `.npmrc` with custom registry | 🟡 | Registry hijack |
| R12 | `pull_request_target` in CI | 🟡 | CI injection |
| R13 | Unpinned GitHub Actions (`@main`) | 🟠 | Action hijack |
| R14 | `--privileged` / host bind-mount in Docker ✨ | 🟡 | Container escape |
| R15 | Base64/hex blob >500 chars | 🟡 | Hidden payload |
| R16 | `~/.ssh`, `~/.aws`, `~/.config/solana`, `~/.gnupg` | 🔴 | Credential theft |
| R17 | `wallet.dat`, `keystore/`, MetaMask/Phantom paths | 🔴 | Wallet targeting |
| R18 | `/dev/tcp/`, `nc -e`, `bash -i` | 🔴 | Reverse shell |
| R19 | `String.fromCharCode` with long numeric arrays | 🟡 | Obfuscation |
| R20 | `.svg` containing `<script>` or JS | 🔴 | SVG malware (Lazarus) |
| **R21** | `.yarnrc.yml` custom `npmRegistryServer`, or **any file in `.yarn/plugins/`** ✨ | 🔴 | Yarn plugins are arbitrary JS executed by every yarn command |
| **R22** | `setup.py` / `conftest.py` / `sitecustomize.py` with exec or network ✨ | 🔴 | `pip install` and `pytest` both run these |
| **R23** | Bidirectional Unicode or homoglyphs in source ✨ | 🔴 | Trojan Source — code reads differently than it runs |
| **R24** | Code pushed off-screen by >200 chars of whitespace ✨ | 🟡 | Hidden-in-plain-sight payload |
| **R25** | Committed native binaries (`.node`, `.so`, `.dylib`, `.dll`, `.exe`) ✨ | 🟡 | Precompiled, unauditable |
| **R26** | Lockfile entries resolving off-registry (git/http tarballs) ✨ | 🟡 | Dependency substitution |
| **R27** | `go.mod` `replace` → third-party fork ✨ | 🟡 | Dependency substitution |
| **R28** | Discord/Telegram webhooks, pastebin, ngrok, raw IP:port ✨ | 🟡 | Exfil endpoint |
| **R29** | `.env` / `process.env` enumeration near a network call ✨ | 🔴 | Secret exfil |
| **R30** | `.devcontainer` / `.idea` with lifecycle commands ✨ | 🟡 | Auto-exec on open |
| **R31** | Single-line minified JS >5 000 chars outside `dist/` ✨ | 🟠 | Hidden logic |

Every rule hit flags its file for Phase 2.

### 2.4 Gemini (Phase 2)

Only flagged files. Batched, truncated to a byte budget, `responseMimeType: application/json` with a response schema so parsing can't drift. Prompt frames it as Contagious Interview triage and demands plain-English execution-flow narration. **Fails open**: no key or an API error degrades to a Phase-1-only report with a `degraded` note — it never takes the scan down.

### 2.5 Scorer

Critical 25 / High 15 / Medium 8 / Low 3, ×1.5 when AI-confirmed, capped at 100. Verdict: 0–30 safe, 31–60 caution, 61–100 danger. Any single critical finding floors the score at 61 — one reverse shell is a danger verdict regardless of arithmetic.

### 2.6 Remediation ✨ (new module)

The first draft ended at "recommendations." A developer staring at a red report needs commands, not advice. Generate a copy-pasteable plan from the actual findings:

- Inspect without executing: `git clone --no-checkout … && git -C … log --stat`
- Install without lifecycle scripts: `npm install --ignore-scripts` / `yarn --mode=skip-build`
- Open in a container, not the host: generated `.devcontainer` snippet
- Per-finding: "delete `.vscode/tasks.json` before opening this folder in VS Code"

---

## 3 — GitHub Client (`lib/github.ts`)

- [ ] **3.1** `parseRepoInput()` — accepts URL, `owner/repo`, `git@` SSH, with `/tree/{ref}`, `#{sha}`
- [ ] **3.2** `resolveRef()` → commit SHA (pin the scan; a re-push is a new report)
- [ ] **3.3** `fetchTree()` — `git/trees/{sha}?recursive=1`, handle `truncated`
- [ ] **3.4** `fetchFiles()` — parallel, budget-capped, base64-decoded
- [ ] **3.5** Typed errors: `NOT_FOUND` / `NEEDS_AUTH` / `RATE_LIMITED` / `TOO_LARGE`, each mapped to a distinct UI state (the difference between "doesn't exist" and "you can't see it" is the whole product)

---

## 4 — App (`app/`)

### 4.1 Landing `/`
Hero, the Lazarus problem stated in two sentences, **a scan box that works with no sign-in**, and a "See a real attack" button loading a bundled sample. No wall.

### 4.2 Scan `/scan`
Input + repo picker (when signed in: `affiliation=owner,collaborator`, sorted by `pushed_at` — the recruiter's repo is top of the list). Live SSE progress: resolving → tree → fetching *n* files → static analysis → AI on *n* flagged → done.

### 4.3 Report `/report/[id]`
Score ring, profile, findings grouped by severity and expandable (path, snippet with the matched span highlighted, AI explanation, per-finding fix), `🔍 Static` / `🤖 AI` phase badges, the action plan, export JSON / copy Markdown.

### 4.4 History `/history`
localStorage-backed, keyed by report id, with re-scan.

### 4.5 API
`POST /api/scan` (SSE) · `GET /api/repos` · `GET /api/me` · `GET /api/auth/github[/callback]` · `POST /api/auth/logout`

### 4.6 Samples (`lib/samples/`) ✨
Bundled fixtures reproducing real Contagious Interview TTPs — `folderOpen` task, base64 `postinstall` dropper, JS-in-SVG, `~/.config/solana` exfil. Served through the identical analyzer path, no GitHub call. **Build this early**: it's the demo, and it's the test fixture.

---

## 5 — Chainlink CRE (`cre/`)

`handlerInTee` fetches both secrets inside the enclave, calls the *same* `analyzeRepo()`, and emits only `{ commit, threatScore, verdict, findingCount }` to the DON — the repo contents and the token never leave.

```ts
export default handlerInTee(trigger, async (runtime) => {
  const geminiKey   = await runtime.getSecret({ id: 'GEMINI_API_KEY' });
  const githubToken = await runtime.getSecret({ id: 'GITHUB_TOKEN' });
  const tree     = await fetchTree(trigger.repo, githubToken);
  const contents = await fetchFiles(tree, githubToken);
  const report   = await analyzeRepo(trigger.repo, tree, contents, geminiKey);
  return runtime.usingTheDons().reportFromDon({
    commit: trigger.commit,
    threatScore: report.threatScore,
    verdict: report.verdict,
  });
}, tees);
```

Track requirements this satisfies: confidential handler ✅, sensitive input processed in-enclave (OAuth token + private repo source) ✅, core to the app ✅. Deliverable: CRE CLI simulation output in the submission.

**Optional (Chainlink-Powered Upgrade track, needs an onchain state change):** a `ScanRegistry` contract mapping `commitSha → threatScore`, written from the DON. Turns the tool into a public good — "has anyone scanned this commit before?" — and satisfies the onchain-state-change requirement the Confidential Workflow track doesn't.

---

## 6 — Polish

- [ ] Distinct empty/error states per GitHub error code
- [ ] Rate-limit budget shown before the scan, not after it fails
- [ ] Truncated-tree warning (huge monorepos)
- [ ] Responsive + dark mode
- [ ] README: architecture diagram, setup, CRE simulation transcript
- [ ] 2–4 min demo video: paste sample → red report → action plan → CRE terminal output

---

## Build Order

**Samples + Analyzer** (testable with zero infra) → **GitHub client** → **API + SSE** → **UI** → **Auth** → **CRE wrapper** → **Polish**

The analyzer is the heart; the samples are how we know it beats. Everything else wraps around them.

---

## Environment

```
# .env.local
SESSION_SECRET=            # 32+ random bytes, hex — openssl rand -hex 32
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
GITHUB_TOKEN=              # optional: raises the anonymous-tier rate limit
GEMINI_API_KEY=            # optional in dev: absent → Phase 1 only, degraded note
NEXT_PUBLIC_APP_URL=http://localhost:3000
```

OAuth App callback: `http://localhost:3000/api/auth/github/callback`
