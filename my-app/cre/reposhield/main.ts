import { Runner, cre, handlerInTee } from "@chainlink/cre-sdk";
import type {
  HTTPPayload,
  TeeRuntime,
  Workflow,
} from "@chainlink/cre-sdk";

import { utf8Decode } from "../../lib/analyzer/portable";
import { createConfidentialHttpClient } from "./http-cre";
import { runConfidentialScan, type ScanRequest, type ScanVerdict } from "./scan";

/**
 * RepoShield as a Chainlink CRE Confidential Workflow.
 *
 * A developer is sent a private GitHub repository as a "coding assignment".
 * To find out whether it is hostile, something has to read it — and reading it
 * means holding a token with read access to their private repositories, and
 * shipping their employer's source to an LLM.
 *
 * This handler does all of that inside a TEE. Three things that must not be
 * visible to the node operator or to RepoShield's own servers pass through the
 * enclave:
 *
 *   1. the GitHub token          (Vault DON secret)
 *   2. the Gemini API key        (Vault DON secret)
 *   3. the private repo's source (confidential input, fetched and analysed
 *                                 without ever leaving the enclave)
 *
 * Only an aggregate verdict crosses back to the DON. The findings quote
 * repository source verbatim, so emitting them would publish exactly the code
 * this arrangement exists to protect.
 *
 * The analysis itself is the same `analyzeRepo` the web app runs — see
 * ../README.md for what making one engine run in both places required.
 */

export interface Config {
  /** Vault DON secret ids, indirected through config as the template does. */
  secrets_ids: {
    github_token_id: string;
    gemini_api_key_id: string;
  };
  /**
   * API origins. In production these are the real hosts; `cre workflow
   * simulate` points them at the local mock server, since the simulator has no
   * route to the public internet.
   */
  github_api_base: string;
  gemini_endpoint_base: string;
}

async function onScanRequest(
  runtime: TeeRuntime<Config>,
  payload: HTTPPayload,
): Promise<ScanVerdict> {
  const { secrets_ids, github_api_base, gemini_endpoint_base } = runtime.config;

  const request = JSON.parse(utf8Decode(payload.input)) as ScanRequest;
  runtime.log(`reposhield-scan-request repo=${request?.repo ?? "(none)"}`);

  // Both secrets in one call, decrypted inside the enclave.
  const secrets = runtime
    .getSecrets([
      { id: secrets_ids.github_token_id },
      { id: secrets_ids.gemini_api_key_id },
    ])
    .result();

  runtime.log("reposhield-getsecrets-ok");

  const verdict = await runConfidentialScan(request, {
    getSecret: (id) => {
      const secret = secrets[id];
      if (!secret) throw new Error(`secret not provisioned: ${id}`);
      return secret.value;
    },
    // Every outbound call goes through confidential-http, so the token in the
    // Authorization header and the source code in the Gemini request body are
    // sent from inside the TEE rather than by the node.
    http: createConfidentialHttpClient(runtime),
    log: (message) => runtime.log(message),
    githubApiBase: github_api_base,
    geminiEndpointBase: gemini_endpoint_base,
    githubTokenId: secrets_ids.github_token_id,
    geminiKeyId: secrets_ids.gemini_api_key_id,
  });

  runtime.log(
    `reposhield-verdict repo=${verdict.repo} score=${verdict.threatScore} ` +
      `verdict=${verdict.verdict} findings=${verdict.findingCount} ` +
      `critical=${verdict.criticalCount}`,
  );

  return verdict;
}

/**
 * Map the config's secret ids onto the token ids the scan asks for.
 *
 * `runConfidentialScan` requests `GITHUB_TOKEN` and `GEMINI_API_KEY` by name;
 * the vault may hold them under different ids. This keeps the confidential
 * body independent of how any particular deployment names its secrets.
 */
export const initWorkflow = (config: Config): Workflow<Config> => {
  if (!config?.secrets_ids?.github_token_id || !config?.secrets_ids?.gemini_api_key_id) {
    throw new Error("config requires secrets_ids.github_token_id and .gemini_api_key_id");
  }
  if (!config.github_api_base || !config.gemini_endpoint_base) {
    throw new Error("config requires github_api_base and gemini_endpoint_base");
  }

  return [
    handlerInTee(
      // `authorizedKeys` is populated at deploy time with the public key that
      // signs scan requests; left empty the trigger accepts none.
      new cre.capabilities.HTTPCapability().trigger({}),
      onScanRequest,
      // Any registered TEE, any region. Pinning would read
      // `[{ tee: "nitro", regions: ["us-west-2"] }]` — currently the only
      // binding the SDK offers, so pinning buys nothing but a failure mode.
      {},
    ),
  ];
};

const DEFAULT_CONFIG: Config = {
  secrets_ids: {
    github_token_id: "github_token",
    gemini_api_key_id: "gemini_api_key",
  },
  github_api_base: "https://api.github.com",
  gemini_endpoint_base: "https://generativelanguage.googleapis.com/v1beta",
};

export async function main() {
  const runner = await Runner.newRunner<Config>({
    configParser: (raw: Uint8Array) => {
      const text = utf8Decode(raw);
      if (!text || text.trim() === "") return DEFAULT_CONFIG;
      return JSON.parse(text) as Config;
    },
  });
  await runner.run(initWorkflow);
}

main();
