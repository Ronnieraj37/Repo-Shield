import "server-only";
import { createHash } from "node:crypto";
import stringify from "json-stable-stringify";
import { parseSignature, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";

/**
 * Authentication for a deployed CRE workflow's HTTP trigger.
 *
 * The gateway does not take an API key. It takes a JWT with `alg: "ETH"`,
 * signed by a key whose address appears in the workflow's `authorizedKeys`.
 * This is a port of Chainlink's own reference implementation
 * (`smartcontractkit/cre-sdk-typescript`, `packages/cre-http-trigger`), which
 * is not published to npm.
 *
 * Two details are load-bearing and easy to get wrong:
 *
 *   - The `digest` is SHA-256 over the request serialised with **keys sorted
 *     lexicographically at every nesting level**. The gateway recomputes it
 *     the same way, so ordinary `JSON.stringify` produces a digest mismatch
 *     and a rejected request.
 *   - The same canonical string must be sent as the HTTP body, or the body the
 *     gateway hashes will not be the body we signed.
 */

export interface WorkflowSelector {
  /** 64 hex characters, no `0x` prefix. */
  workflowID: string;
}

export interface JsonRpcRequest {
  jsonrpc: string;
  id: string;
  method: string;
  params: {
    input: unknown;
    workflow: WorkflowSelector;
  };
}

/** JWT lifetime. The gateway rejects anything longer than five minutes. */
const TTL_SECONDS = 300;

const base64Url = (value: string): string =>
  value.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");

function canonical(request: JsonRpcRequest): string {
  return stringify(request) ?? "";
}

export function buildRequest(
  workflowId: string,
  input: unknown,
): JsonRpcRequest {
  return {
    jsonrpc: "2.0",
    id: crypto.randomUUID(),
    method: "workflows.execute",
    params: { input, workflow: { workflowID: workflowId } },
  };
}

export async function createJwt(
  request: JsonRpcRequest,
  privateKey: Hex,
): Promise<string> {
  const account = privateKeyToAccount(privateKey);
  const now = Math.floor(Date.now() / 1000);

  const header = { alg: "ETH", typ: "JWT" };
  const payload = {
    digest: `0x${createHash("sha256").update(canonical(request)).digest("hex")}`,
    iss: account.address,
    iat: now,
    exp: now + TTL_SECONDS,
    jti: crypto.randomUUID(),
  };

  const encodedHeader = base64Url(
    Buffer.from(JSON.stringify(header), "utf8").toString("base64"),
  );
  const encodedPayload = base64Url(
    Buffer.from(JSON.stringify(payload), "utf8").toString("base64"),
  );
  const message = `${encodedHeader}.${encodedPayload}`;

  // viem's signMessage applies the Ethereum signed-message prefix and Keccak256.
  const signature = await account.signMessage({ message });

  // The gateway wants raw r‖s‖v bytes, not the hex signature string.
  const { r, s, v, yParity } = parseSignature(signature);
  // `27n` would need an ES2020 target; the app compiles to ES2017.
  const OFFSET = BigInt(27);
  const recoveryId = v !== undefined ? (v >= OFFSET ? v - OFFSET : v) : yParity;
  if (recoveryId === undefined) {
    throw new Error("Could not extract a recovery id from the signature.");
  }

  const bytes = Buffer.concat([
    Buffer.from(r.slice(2).padStart(64, "0"), "hex"),
    Buffer.from(s.slice(2).padStart(64, "0"), "hex"),
    Buffer.from([Number(recoveryId)]),
  ]);

  return `${message}.${base64Url(bytes.toString("base64"))}`;
}

/** The exact bytes to send, so the body matches the signed digest. */
export function canonicalBody(request: JsonRpcRequest): string {
  return canonical(request);
}

/** The address that must appear in the workflow's `authorizedKeys`. */
export function signerAddress(privateKey: Hex): string {
  return privateKeyToAccount(privateKey).address;
}
