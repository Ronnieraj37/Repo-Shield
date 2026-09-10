import { cre, text } from "@chainlink/cre-sdk";
import type { TeeRuntime } from "@chainlink/cre-sdk";
import type { HttpClient, HttpRequest, HttpResponse } from "../../lib/analyzer/http";

/**
 * An `HttpClient` backed by CRE's HTTP capability, called from inside the TEE.
 *
 * This is why the analyzer takes an injected transport: there is no `fetch`
 * inside the enclave, and outbound requests must go through a capability so
 * that the GitHub API call carrying the developer's OAuth token, and the
 * Gemini call carrying their private source, are made from within the TEE
 * rather than by the node.
 *
 * Note which client this is. `ConfidentialHTTPClient` looks like the obvious
 * choice by name and is the wrong one — it has no `TeeRuntime` overload and is
 * not meant to be called from a TEE handler. `HTTPClient.sendRequest()` does
 * have one, so passing the `TeeRuntime` straight in is what keeps the request
 * and response payloads confidential from node operators.
 *
 * Two shape differences from `fetch` are handled here: the call is synchronous,
 * returning a handle whose `.result()` blocks, and the response body arrives as
 * bytes rather than text.
 */
export function createTeeHttpClient(runtime: TeeRuntime<unknown>): HttpClient {
  const client = new cre.capabilities.HTTPClient();

  return {
    async send(request: HttpRequest): Promise<HttpResponse> {
      try {
        const response = client
          .sendRequest(runtime, {
            url: request.url,
            method: request.method ?? "GET",
            ...(request.headers
              ? {
                  multiHeaders: Object.fromEntries(
                    Object.entries(request.headers).map(([name, value]) => [
                      name,
                      { values: [value] },
                    ]),
                  ),
                }
              : {}),
            ...(request.body ? { body: request.body } : {}),
          })
          .result();

        return { status: response.statusCode, body: text(response) };
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
