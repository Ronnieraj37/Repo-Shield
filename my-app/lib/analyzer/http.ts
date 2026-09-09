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
  /**
   * Ask for the raw bytes instead of text. Used for repository tarballs, which
   * are gzip and would be destroyed by UTF-8 decoding.
   */
  responseType?: "text" | "bytes";
  /**
   * Set false to receive the 3xx instead of following it.
   *
   * GitHub's tarball endpoint redirects across origins to codeload.github.com.
   * The token authorises the first hop only — codeload does not want it, and
   * runtimes strip `Authorization` on an origin change regardless, which would
   * silently fail every private repository if we let the redirect be followed
   * automatically.
   */
  followRedirects?: boolean;
}

export interface HttpResponse {
  status: number;
  body: string;
  /** Populated instead of `body` when `responseType: "bytes"` was requested. */
  bytes?: Uint8Array;
  headers?: Record<string, string>;
}

export interface HttpClient {
  send(request: HttpRequest): Promise<HttpResponse>;
}
