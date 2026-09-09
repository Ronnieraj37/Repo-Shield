import type { ActionStep, Finding, ProjectProfile, Verdict } from "./types";

/**
 * Turn findings into things the developer can actually do.
 *
 * A severity badge tells someone they have a problem; it does not tell them
 * what to type. Every step here is either a command they can paste or a
 * specific file they can delete.
 */
export function buildActionPlan(
  findings: Finding[],
  profile: ProjectProfile,
  verdict: Verdict,
  repoUrl: string,
): ActionStep[] {
  const steps: ActionStep[] = [];
  const has = (ruleId: string) => findings.some((f) => f.ruleId === ruleId);
  const filesFor = (ruleId: string) => [
    ...new Set(findings.filter((f) => f.ruleId === ruleId).map((f) => f.file)),
  ];

  if (verdict === "danger") {
    steps.push({
      priority: 0,
      title: "Do not run this on your own machine",
      detail:
        "The findings below execute without an explicit command from you — opening the folder or installing dependencies is enough. Anything you do with this repo should happen in a disposable VM or container.",
    });
  }

  // Always useful: read the code without ever checking it out.
  steps.push({
    priority: 1,
    title: "Inspect it without checking anything out",
    detail:
      "A bare clone downloads the history without writing any working files to disk, so nothing can auto-run. You can browse it entirely from the command line.",
    command: `git clone --bare ${repoUrl} repo-inspect.git\ncd repo-inspect.git && git log --stat -20`,
  });

  if (has("R06") || has("R06b") || has("R30")) {
    const files = [...filesFor("R06"), ...filesFor("R06b"), ...filesFor("R30")];
    steps.push({
      priority: 0,
      title: "Delete the editor config before opening the folder",
      detail: `${files.join(", ")} can execute commands the moment this project is opened in VS Code — before you read anything. Remove these files first, from a terminal, not from inside the editor.`,
      command: `rm -rf .vscode .devcontainer .idea`,
    });
  }

  const isNode = profile.frameworks.some((f) =>
    ["nodejs", "hardhat", "truffle", "bun", "deno"].includes(f),
  );
  if (isNode && (has("R01") || has("R02") || has("R05") || verdict !== "safe")) {
    const yarn = profile.packageManagers.includes("yarn");
    steps.push({
      priority: 2,
      title: "Install without running lifecycle scripts",
      detail:
        "`preinstall`, `install`, and `postinstall` scripts run automatically and are the most common execution vector. These flags skip them. Note that this may leave native modules unbuilt — which is fine, because you are reading the code, not shipping it.",
      command: yarn
        ? `yarn install --mode=skip-build`
        : `npm install --ignore-scripts`,
    });
  }

  if (has("R21")) {
    steps.push({
      priority: 0,
      title: "Remove Yarn's repo-local configuration first",
      detail:
        "Yarn loads plugins from `.yarn/plugins/` and reads `.yarnrc.yml` on every command, including `yarn --version`. Deleting them is the only way to run yarn here safely.",
      command: `rm -rf .yarn/plugins .yarnrc.yml`,
    });
  }

  if (has("R11") || has("R26")) {
    steps.push({
      priority: 2,
      title: "Check where packages would actually come from",
      detail:
        "This repo redirects package resolution. Confirm the effective registry before installing anything.",
      command: `npm config get registry\nnpm config list`,
    });
  }

  if (profile.frameworks.includes("foundry") && has("R07")) {
    steps.push({
      priority: 2,
      title: "Audit every FFI call before running the tests",
      detail:
        "With `ffi = true`, `forge test` can run any shell command the test suite chooses. Read each call site first.",
      command: `grep -rn "vm.ffi(" test/ src/ script/`,
    });
  }

  if (profile.frameworks.includes("cargo") && has("R08")) {
    steps.push({
      priority: 2,
      title: "Read build.rs before running cargo",
      detail:
        "`build.rs` executes during `cargo build`, `cargo test`, and even `cargo check`. There is no flag to skip it.",
      command: `cat build.rs`,
    });
  }

  if (profile.frameworks.includes("python") && has("R22")) {
    steps.push({
      priority: 2,
      title: "Read setup.py and conftest.py before pip or pytest",
      detail:
        "`pip install` executes `setup.py`; `pytest` imports `conftest.py` at startup. Both run before any test does.",
      command: `cat setup.py conftest.py 2>/dev/null`,
    });
  }

  if (has("R16") || has("R17") || has("R29")) {
    steps.push({
      priority: 0,
      title: "If you already ran this, rotate your credentials now",
      detail:
        "This repo references SSH keys, wallet storage, or your environment variables. If any of its code has already executed on your machine, treat those secrets as taken: move funds out of hot wallets, rotate API keys, and replace SSH keys.",
    });
  }

  if (verdict !== "safe") {
    steps.push({
      priority: 3,
      title: "If you need to run it, run it in a container",
      detail:
        "This gives the code a filesystem of its own with no access to your keys, your shell environment, or your network credentials.",
      command: `docker run --rm -it --network none -v "$PWD":/src:ro -w /src node:22 bash`,
    });
  }

  if (verdict === "danger") {
    steps.push({
      priority: 4,
      title: "Report it",
      detail:
        "GitHub takes down repositories used in fake-recruitment campaigns, and reporting protects the next candidate who gets the same message. Report the repo and the account that sent it to you.",
    });
  }

  return steps.sort((a, b) => a.priority - b.priority);
}
