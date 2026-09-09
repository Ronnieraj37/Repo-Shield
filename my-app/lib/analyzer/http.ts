/**
 * The analyzer's only window to the network.
 *
 * `fetch` does not exist in the Chainlink CRE WASM runtime — outbound requests
 * there go through the confidential-http capability, which is synchronous and
 * shaped nothing like `fetch`. So the engine never calls `fetch` itself; it
 * asks for an `HttpClient` and the caller supplies one:
 *
 *   - the web app passes a fetch-backed client with timeouts and retries
 *   - the CRE workflow passes one backed by `confidential-http`, so the
 *     request never leaves the enclave in the clear
 *
 * Timeouts, retries and backoff belong to the adapter, not here — `setTimeout`
 * is also unavailable inside the enclave.
 */

export interface HttpRequest {
  url: string;
  method?: "GET" | "POST";
  headers?: Record<string, string>;
  body?: string;
}

export interface HttpResponse {
  status: number;
  body: string;
  headers?: Record<string, string>;
}

export interface HttpClient {
  send(request: HttpRequest): Promise<HttpResponse>;
}
