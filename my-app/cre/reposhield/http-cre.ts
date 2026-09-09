import { cre, httpRequest } from "@chainlink/cre-sdk";
import type { Runtime, TeeRuntime } from "@chainlink/cre-sdk";
import type { HttpClient, HttpRequest, HttpResponse } from "../../lib/analyzer/http";
import { utf8Decode } from "../../lib/analyzer/portable";

/**
 * An `HttpClient` backed by CRE's confidential-http capability.
 *
 * This is the whole reason the analyzer takes an injected transport: inside
 * the enclave there is no `fetch`, and outbound requests must go through a
 * capability so that the request — GitHub's API URL carrying the developer's
 * OAuth token, and the Gemini call carrying their private source code — is
 * made from inside the TEE rather than from the node.
 *
 * Two shape differences from `fetch` are handled here:
 *   - the call is synchronous, returning a handle whose `.result()` blocks,
 *     so it is wrapped to satisfy the promise-based interface
 *   - the response body arrives as bytes, not text
 */
export function createConfidentialHttpClient(
  runtime: TeeRuntime<unknown>,
): HttpClient {
  const client = new cre.capabilities.ConfidentialHTTPClient();

  return {
    async send(request: HttpRequest): Promise<HttpResponse> {
      try {
        // `ConfidentialHTTPRequest` wraps the HTTP request itself alongside an
        // optional list of vault secrets. The generic is passed explicitly
        // because `sendRequest`'s parameter is a conditional type
        // (`CapabilityInput<...>`) and TypeScript cannot infer a type variable
        // from one of those — left to inference it widens to `unknown` and
        // rejects every field.
        const response = client
          .sendRequest<{ request: ReturnType<typeof httpRequest> }>(
            // Typed against `Runtime`, but a `TeeRuntime` carries the same
            // `callCapability` surface and is what we must pass — routing this
            // through `usingTheDons()` would issue the request from outside
            // the enclave, defeating the point.
            runtime as unknown as Runtime<unknown>,
            {
              request: httpRequest({
                url: request.url,
                method: request.method ?? "GET",
                headers: request.headers,
                body: request.body,
              }),
            },
          )
          .result();

        return {
          status: response.statusCode,
          body: utf8Decode(response.body),
        };
      } catch (error) {
        // Mirror the web adapter: transport failures come back as a response
        // so callers have exactly one code path to handle.
        return {
          status: 599,
          body: error instanceof Error ? error.message : "capability call failed",
        };
      }
    },
  };
}
