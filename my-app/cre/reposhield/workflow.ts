import { cre } from "@chainlink/cre-sdk";
import type { HTTPPayload, TeeRuntime } from "@chainlink/cre-sdk";
import { z } from "zod";

import { utf8Decode } from "../../lib/analyzer/portable";
import { createTeeHttpClient } from "./http-cre";
import { runConfidentialScan, type ScanRequest, type ScanVerdict } from "./scan";

/**
 * RepoShield as a Chainlink CRE Confidential Workflow.
 *
 * A developer is sent a private GitHub repository as a "coding assignment".
 * Finding out whether it is hostile means reading it — which means holding a
 * token that can read all of their private repositories, and shipping someone
 * else's source to an LLM. GitHub offers no read-only scope that reaches a
 * repository you were invited to as an outside collaborator, so there is no
 * narrower credential to ask for.
 *
 * This handler does all of it inside a TEE. Three things that must not be
 * visible to the node operator or to RepoShield's own servers pass through the
 * enclave: the GitHub token, the Gemini API key, and the repository's source.
 * Only an aggregate verdict crosses back to the DON — the findings quote that
 * source verbatim, so emitting them would publish exactly what the enclave
 * exists to protect.
 *
 * The analysis is the same `analyzeRepo` the web app runs, not a port of it.
 * See ../README.md for what making one engine run in both places required.
 */

export const configSchema = z.object({
  /** Vault secret ids, indirected through config as the templates do. */
  githubTokenSecretId: z.string(),
  geminiApiKeySecretId: z.string(),
  /**
   * API origins. In production these are the real hosts; `cre workflow
   * simulate` points them at a local mock, since the simulator has no route to
   * the public internet.
   */
  githubApiBase: z.string(),
  geminiEndpointBase: z.string(),
  /**
   * EVM addresses permitted to trigger this workflow.
   *
   * The HTTP trigger authenticates callers by an ECDSA signature over the
   * JWT, so an empty list means the deployed workflow accepts nothing. This
   * holds the address of the key the web app signs with.
   */
  authorizedKeys: z.array(z.string()).default([]),
});

export type Config = z.infer<typeof configSchema>;

export const onScanRequest = async (
  runtime: TeeRuntime<Config>,
  payload: HTTPPayload,
): Promise<ScanVerdict> => {
  const config = runtime.config;

  const request = JSON.parse(utf8Decode(payload.input)) as ScanRequest;
  runtime.log(`reposhield-scan-request repo=${request?.repo ?? "(none)"}`);

  // Both secrets in one call. The Vault DON releases them only into an
  // attested enclave, and they are decrypted at the moment this runs.
  const secrets = runtime
    .getSecrets([
      { id: config.githubTokenSecretId },
      { id: config.geminiApiKeySecretId },
    ])
    .result();

  runtime.log("reposhield-getsecrets-ok");

  const verdict = await runConfidentialScan(request, {
    getSecret: (id) => {
      const secret = secrets[id];
      if (!secret) throw new Error(`secret not provisioned: ${id}`);
      return secret.value;
    },
    http: createTeeHttpClient(runtime),
    log: (message) => runtime.log(message),
    githubApiBase: config.githubApiBase,
    geminiEndpointBase: config.geminiEndpointBase,
    githubTokenId: config.githubTokenSecretId,
    geminiKeyId: config.geminiApiKeySecretId,
  });

  runtime.log(
    `reposhield-verdict repo=${verdict.repo} score=${verdict.threatScore} ` +
      `verdict=${verdict.verdict} findings=${verdict.findingCount} ` +
      `critical=${verdict.criticalCount}`,
  );

  return verdict;
};

export function initWorkflow(config: Config) {
  const httpTrigger = new cre.capabilities.HTTPCapability();

  return [
    // `{}` as the TEE constraint means any registered enclave, any region.
    // Pinning would read `[{ tee: "nitro", regions: ["us-west-2"] }]` — the
    // only registered combination today, so pinning buys a failure mode and
    // nothing else.
    cre.handlerInTee(
      httpTrigger.trigger({
        authorizedKeys: config.authorizedKeys.map((publicKey) => ({
          type: "KEY_TYPE_ECDSA_EVM" as const,
          publicKey,
        })),
      }),
      onScanRequest,
      {},
    ),
  ];
}
