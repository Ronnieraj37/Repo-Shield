## Problem

The problem we want to solve is the **security risk faced by developers when applying for jobs, especially in Web3**.

Many companies send candidates coding assignments through GitHub repositories. While most are legitimate, some fake recruitment offers use these assignments as a way to distribute **malicious or compromised code**. A candidate may be instructed to clone the repository and run commands such as `npm install`, `yarn install`, `cargo build`, or setup scripts. These can automatically execute malicious code, download additional payloads, steal credentials, access SSH keys or crypto-wallet data, or compromise the developer's machine.

The problem is that **a GitHub repository can look completely normal when viewed manually**, and most developers don't have the time, expertise, or isolated infrastructure to safely determine what will happen when they run it.

We want to solve this by allowing a developer to:

> **Paste an unfamiliar GitHub repository and understand whether it is safe to run — without having to run it on their own computer.**

The system should inspect the repository's configuration files, scripts, and dependencies using a two-phase pipeline — fast static heuristics followed by targeted AI analysis — and present the findings in a simple report that a normal developer can understand.

The goal isn't to claim that a repository is absolutely "safe," but to give developers **evidence-based visibility into what the repository contains and what it actually does when executed**, before they put their own machine, credentials, or assets at risk.

---

## The Market Gap: Why Existing Tools Fail

Tools like **Socket.dev**, **Snyk**, and **ScanRepo** exist, but they all suffer from a fatal flaw when it comes to the "Contagious Interview" attacks (a real, highly active campaign run by the **North Korean Lazarus Group**).

### The Private Repo Trap

Existing supply-chain security tools are built for **repository owners**. They require you to install a GitHub App or set up a GitHub Action CI/CD pipeline.

When a fake recruiter invites a developer to a private GitHub repository for a "technical test," the developer only has **Read Access**. They cannot install Socket.dev. They cannot add a GitHub Action. Public scanners cannot see it.

The developer's only options are to **clone it blindly or walk away**.

### Our Unfair Advantage

By allowing developers to safely authenticate with GitHub OAuth — and having the analysis run inside a **Chainlink CRE Trusted Execution Environment** — we are building the **first candidate-centric security tool**, rather than an enterprise-centric one.

The developer's GitHub token is used *only* inside a hardware-secured enclave to fetch repo files, and is immediately destroyed. Zero trust required.

---

## Solution: Two-Phase Analysis Pipeline

### The Core Insight

Hackers are getting incredibly creative. Recent Lazarus attacks didn't just use `npm install` hooks. They:
- Hid malware inside **`.vscode/tasks.json`** files (auto-executes when you open the folder in VS Code)
- Hid Base64-encoded JavaScript inside innocent-looking **`.svg`** image files
- Used typosquatted npm packages that look identical to real ones

**Static analysis alone will miss these. AI alone is too slow and expensive to read a whole repository.** The answer is a pipeline.

### Phase 1: Static Filter (Fast & Cheap)

Run locally inside the Chainlink CRE environment using regex and heuristic rules. No API calls needed.

* **Suspicious files:** `.vscode/tasks.json`, `.npmrc`, complex `postcss.config.js`, shell scripts in root
* **Obfuscation indicators:** `eval()`, `Function()`, `child_process`, `Buffer.from(…, 'base64')`, massive hex/base64 strings
* **Lifecycle script abuse:** `preinstall`, `postinstall` containing `curl | bash`, `node -e`, or encoded payloads
* **Package checks:** Typosquatted dependency names (Levenshtein distance), unpinned versions, suspicious `overrides`/`resolutions`
* **Framework-specific:** Foundry `ffi = true`, Cargo `build.rs`, CI `pull_request_target`

**This phase is the filter.** It identifies the 5-10 files that need expert analysis.

### Phase 2: Gemini API for Contextual Intent (Smart & Targeted)

Only flagged files from Phase 1 are sent to the **Gemini API** for deep analysis.

Because Gemini has massive context windows and deep code reasoning, it excels at:
- Deciphering obfuscated logic in install scripts
- Recognizing a fake `.svg` file is actually an obfuscated Node.js backdoor
- Explaining the execution flow in plain English for the developer
- Catching zero-day obfuscation patterns that static rules miss

**Prompt design:**
> *"You are an expert malware analyst. I am providing a script found in a Web3 developer interview repository. Does this code attempt to access local credentials (like ~/.ssh or ~/.config/solana), establish a reverse shell, or exfiltrate data? Explain exactly what the execution flow does."*

By running static filtering first and using Gemini as the "expert analyst" for suspicious snippets only, the tool is **fast, cost-effective, and capable of catching novel attacks**.

---

## Architecture

### Delivery Strategy: Web App + GitHub OAuth

A **Next.js Web App** where the developer signs in with GitHub OAuth. Their read-only access token is used inside the Chainlink CRE TEE to fetch repository files for analysis. The token never leaves the enclave.

### System Flow

```
Developer signs in with GitHub OAuth
        │
        ▼
Pastes repo URL (public or private)
        │
        ▼
Chainlink CRE handlerInTee (TEE):
  ┌────────────────────────────────────────────┐
  │ 1. Use GitHub token to fetch repo tree     │
  │    + config files via GitHub API           │
  │                                            │
  │ 2. PHASE 1: Static Filter                 │
  │    • Detect project type (Foundry/Hardhat  │
  │      /Cargo/Node/Python/etc.)              │
  │    • Parse configs, scripts, dependencies  │
  │    • Run heuristic rules (regex, patterns) │
  │    • Flag suspicious files                 │
  │                                            │
  │ 3. PHASE 2: Gemini AI Analysis             │
  │    • Send ONLY flagged files to Gemini API │
  │    • Deep analysis of obfuscated code      │
  │    • Plain-English threat explanations     │
  │                                            │
  │ 4. Aggregate → Threat Score + Report       │
  │    • Wipe GitHub token from memory         │
  │    • Return report to frontend             │
  └────────────────────────────────────────────┘
        │
        ▼
Web App displays threat report with:
  • Overall threat score (0-100)
  • Per-file findings with severity badges
  • AI-generated explanations
  • Actionable recommendations
```

### Why Chainlink CRE?

* **Confidentiality:** The developer's GitHub OAuth token and the Gemini API key are decrypted *only* inside the TEE via `runtime.getSecret()`. Neither the node operator nor the application backend ever sees them.
* **Trust:** The developer can verify that their private repo code is analyzed inside a hardware enclave and not stored or leaked.
* **Template:** Based on Chainlink's "AI Smart Contract Audit Firewall" template — same pattern of TEE + AI + structured output.