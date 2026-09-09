# 🛡️ RepoShield

**Know what a repository does before you run it.**

Fake recruiters send developers "take-home assignments" as GitHub repositories.
Opening the folder in VS Code, or running `npm install`, is enough to hand over
your SSH keys and your wallet. The repo reads as completely normal.

RepoShield reads what a repo *executes* — install hooks, editor tasks, build
scripts, CI, package resolution — and tells you in plain English, with the
commands to inspect it safely.

```bash
yarn install
cp .env.example .env.local     # SESSION_SECRET is the only required value
yarn dev
```

Then open <http://localhost:3000> and click **Fake interview assignment** to see
a real attack pattern scored 100/100 — no API keys, no GitHub account, no
network access to anything malicious.

---

## Why this exists

Socket.dev, Snyk, and every other supply-chain scanner is built for repository
**owners**: they need a GitHub App installed or a CI workflow added. When a
"recruiter" invites you to a private repo as an outside collaborator, you have
read access and nothing else. You cannot install anything. Public scanners
cannot see it.

Your options are to clone it blindly or walk away. RepoShield is the third one.

## How it works

Two phases, because neither one is sufficient alone.

**Phase 1 — static filter.** 38 rules over the manifests, editor config,
lockfiles, CI, and build scripts. Fast, free, offline, and it runs on every
scan. This phase's job is to find the five files that need an expert.

**Phase 2 — AI on those files only.** Flagged files go to Gemini, which decodes
obfuscation and explains the execution flow. Nothing else does — that is what
keeps a scan at seconds rather than minutes, and free rather than expensive. On
the bundled malware fixtures, six flagged files are analysed in about 12
seconds; the benign fixture flags nothing and never calls the API at all.

Phase 2 **races two models in parallel** and takes the first answer. This is not
premature optimisation: benchmarking each candidate model three times against
the real payload found the flagship `flash` models returning HTTP 503
"experiencing high demand" one to two times out of three, while the `lite`
models answered 3/3. Racing a strong model against a reliable one turns a
coin-flip into a near certainty without waiting out a backoff.

Phase 2 **fails open**: no API key, every model overloaded, or a malformed
response degrades to a Phase 1 report with a visible note. It never fails a scan.

### What Phase 1 catches that a `package.json` review does not

- `.vscode/tasks.json` with `runOptions.runOn: "folderOpen"` — executes the
  moment you open the folder, before you read a line
- Yarn plugins in `.yarn/plugins/`, which run on *every* yarn command
- `setup.py` / `conftest.py` — executed by `pip install` and `pytest`
- Trojan Source: bidirectional Unicode that makes the code you read differ from
  the code that runs
- Payloads pushed 300 columns right, off the edge of your editor
- JavaScript inside `.svg` files
- Lockfile entries resolving to git or arbitrary tarball URLs
- Credential paths built with `path.join(os.homedir(), ".ssh", …)`, not just
  literal `~/.ssh`
- Browser credential stores — Chrome `Login Data`, Firefox `logins.json`, the
  macOS Keychain, extension storage. This is what BeaverTail, the stealer these
  repos deliver, exists to read
- XOR decode loops — recent samples layer Base64 with XOR specifically to get
  past both scanners and human review
- Droppers that branch on `process.arch` to fetch a per-platform payload
- Obfuscation by *statistics*: entropy, whitespace ratio, `\xNN` density and
  machine-generated `_0xabcd` identifiers, so a packed file is caught even when
  no individual pattern matches

Full table in [`../steps.md`](../steps.md).

## Calibration

A scanner that flags everything gets ignored on the repo that matters, so the
rules are tuned against false positives as deliberately as against attacks.

`yarn test:analyzer` runs four fixtures. Two are malware. One is an ordinary
Hardhat project. The fourth — `benign-tooling` — exists only to be a trap: it
has an install hook, a private npm registry, base64 decoding, `child_process`,
a minified bundle, an SVG, a Dockerfile and unpinned CI actions. It must score
**zero**. Seventeen individual rules are asserted *not* to fire on it.

Three rules were rewritten because of what that testing found:

- **R09 (typosquatting)** flagged `xo` as a typo of `zod`. Short names are dense
  — nearly every three-letter name is within two edits of something popular. It
  now scales its tolerance with length, skips scoped names, and uses
  Damerau-Levenshtein so a transposition (`axois` for `axios`, the commonest
  squat) counts as one edit rather than two. Measured against 88 real
  dependency names: **0 false positives**, while still catching the squats.
- **R05 (base64)** fired on any `Buffer.from(x, "base64")`. That is routine —
  JWTs, inline images, test fixtures. It now only reports a decode that sits
  within a few lines of somewhere the bytes could execute or leave the machine.
- **R11 (npm registry)** flagged every custom registry. A scoped feed
  (`@acme:registry=...`) is how every company with private packages is set up;
  redirecting the *global* registry is the attack. It now distinguishes them.

A dedup bug surfaced during the same work: findings were keyed on
`rule:file:line`, so rules that report several distinct problems in one file
without line numbers — four typosquatted dependencies in one `package.json` —
all collapsed onto one key and only the first survived.

`yarn scan:corpus` runs the engine against ten real, widely used repositories
(`express`, `prettier`, `viem`, `forge-std`, `openzeppelin-contracts`, …). Every
one should come back clean; anything it finds is a false positive until proven
otherwise. It needs `GITHUB_TOKEN` set — ten repos is well past the anonymous
rate limit.

## Large repositories

A file tree arrives in one API call however large the repo is. Every file
*body* is another call against a shared rate limit, so "read everything" only
scales so far. Three regimes:

| Repo size | Strategy | Coverage |
|---|---|---|
| ≤ 45 files | Read all of it | 100% |
| Hundreds | Auto-executing files + risk-ranked source | ~20% |
| Tens of thousands | Auto-executing files + anomalies only | <1% |

Files are ranked by a risk score, not a fixed list: manifests and editor config
score highest, then lockfiles and source, with bumps for a 500 KB file in
`src/`, a hidden directory, a double extension (`logo.svg.js`), or a name like
`tmp`/`backup`. Vendored and build directories never count.

Measured against a synthetic 50,000-file monorepo, RepoShield reads **110 files
(0.22%)** and still catches every planted high-risk file — the `folderOpen`
task, the `.npmrc`, the oversized bundle and the double extension.

The report says so plainly. Below 60% coverage it prints how much was actually
read, and if the verdict is "safe" it qualifies it: *nothing alarming in what
auto-executes* is not *a clean bill of health for 50,000 files*. Coverage is a
number the user sees, not one we bury.

## Access model

GitHub offers **no read-only scope** that can reach a private repo you were
invited to. Fine-grained PATs only reach resources their owner owns; GitHub Apps
can only be installed by someone who admins the account. So there are three
tiers, and the app never demands more than the job needs:

| Tier | When | What we hold |
|---|---|---|
| **Anonymous** | Public repos — the default | Nothing |
| **GitHub OAuth** | Only after a repo comes back private | Token, AES-256-GCM sealed in an httpOnly cookie, 1h TTL |
| **Pasted token** | You would rather not grant OAuth | Held in memory for one request |

Signing out calls `DELETE /applications/{client_id}/grant`, so the grant is
actually gone from your GitHub account — verify at
[github.com/settings/applications](https://github.com/settings/applications).

There is no database. Reports are stored in your browser's `localStorage` and
never uploaded, which is why a report link only works on the device that ran the
scan. Sharing is explicit: **Copy as Markdown** or **JSON**.

## Layout

```
my-app/
├── lib/analyzer/       # the engine — pure, no I/O, runs identically in the TEE
│   ├── detector.ts     #   project type + which files are worth fetching
│   ├── rules.ts        #   phase 1: 31 heuristics
│   ├── gemini.ts       #   phase 2: AI on flagged files only
│   ├── scorer.ts       #   score, verdict, severity floors
│   └── remediation.ts  #   the commands to actually type
├── lib/github.ts       # typed errors — "private" and "missing" are different
├── lib/session.ts      # sealed-cookie sessions, no server store
├── lib/samples/        # inert fixtures: the demo and the test suite
├── app/                # landing · scan console (SSE) · report · history
└── scripts/            # analyzer regression check
cre/                    # Chainlink CRE confidential workflow (scaffold)
```

## Commands

```bash
yarn dev              # http://localhost:3000
yarn build            # production build
yarn typecheck        # tsc --noEmit
yarn test:analyzer    # static engine vs. the fixtures — no network, no keys
yarn test:ai          # phase 2 against the live Gemini API
yarn scan:corpus      # calibration run against ten real repos (needs GITHUB_TOKEN)
```

Run `test:analyzer` after touching `rules.ts`. It is fast, offline, and asserts
both directions: the attacks are caught and the benign fixture stays silent.

## Chainlink CRE

`cre/` is a real workflow, not a sketch. It compiles against
`@chainlink/cre-sdk@1.20.0` and calls **the same `analyzeRepo`** the web app
does — not a port of it.

That only works because the engine is portable. The CRE WASM runtime types
`fetch`, `setTimeout`, `crypto`, `Buffer` and `fs` as `never`, all of which the
first version of the analyzer used. So:

- `lib/analyzer/portable.ts` implements SHA-256, base64 and UTF-8 by hand.
  `scripts/verify-portable.mts` checks every one against Node's `crypto` and
  `Buffer` on a set of vectors, including multi-byte and surrogate-pair input.
- The analyzer never calls `fetch`. It takes an injected `HttpClient`
  (`lib/analyzer/http.ts`). The web app passes a fetch-backed one with timeouts
  and retries; the workflow passes one backed by CRE's **confidential-http**
  capability, so the GitHub token in the `Authorization` header and the private
  source code in the Gemini request body are sent from inside the enclave.
- Retries, backoff and timeouts live in the adapters, never in the engine.

Secrets are read with `runtime.getSecret({ id }).result()` inside the TEE. Only
`{ repo, commit, threatScore, verdict, findingCount, criticalCount }` crosses
back to the DON — findings quote repository source verbatim, so publishing them
would defeat the point of running there.

Setup and what still needs a human: [`cre/README.md`](../cre/README.md).

## Limits, stated plainly

RepoShield reports **evidence about what a repository contains**. It cannot
prove code is safe. A clean report means nothing matched the patterns we know
about — not that there is nothing there. Read the code before you run it.
