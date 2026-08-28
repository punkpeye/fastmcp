import { cancelResponseBody } from "./cancelResponseBody.js";

export class DiscoveryDocumentCache {
  public get size(): number {
    return this.#cache.size;
  }

  #cache: Map<
    string,
    {
      data: unknown;
      expiresAt: number;
    }
  > = new Map();

  #generation = 0;

  #inFlight: Map<string, Promise<unknown>> = new Map();

  #timeoutMs: number;

  #ttl: number;

  #urlGenerations: Map<string, number> = new Map();

  /**
   * @param options - configuration options
   * @param options.timeoutMs - timeout in miliseconds for the upstream fetch
   * @param options.ttl - time-to-live in miliseconds
   */
  public constructor(options: { timeoutMs?: number; ttl?: number } = {}) {
    this.#timeoutMs = options.timeoutMs ?? 10000; // default 10 seconds
    this.#ttl = options.ttl ?? 3600000; // default 1 hour
  }

  /**
   * @param url - optional URL to clear. if omitted, clears all cached documents.
   */
  public clear(url?: string): void {
    if (url) {
      this.#cache.delete(url);
      this.#inFlight.delete(url);
      this.#urlGenerations.set(url, (this.#urlGenerations.get(url) ?? 0) + 1);
    } else {
      this.#cache.clear();
      this.#inFlight.clear();
      this.#urlGenerations.clear();
      this.#generation++;
    }
  }

  /**
   * fetches a discovery document from the given URL.
   * uses cached value if available and not expired.
   * coalesces concurrent requests for the same URL to prevent duplicate fetches.
   *
   * @param url - the discovery document URL (e.g., /.well-known/openid-configuration)
   * @returns the discovery document as a JSON object
   * @throws Error if the fetch fails or returns non-OK status
   */
  public async get(url: string): Promise<unknown> {
    const now = Date.now();
    const cached = this.#cache.get(url);

    // return cached value if still valid
    if (cached && cached.expiresAt > now) {
      return cached.data;
    }

    // check if there’s already an in-flight request for this URL
    const inFlight = this.#inFlight.get(url);

    if (inFlight) {
      return inFlight;
    }

    // create a new fetch promise and store it
    const fetchPromise = this.#fetchAndCache(
      url,
      this.#generation,
      this.#urlGenerations.get(url) ?? 0,
    );

    this.#inFlight.set(url, fetchPromise);

    try {
      const data = await fetchPromise;
      return data;
    } finally {
      // clean up in-flight promise after completion
      // (success or failure)
      if (this.#inFlight.get(url) === fetchPromise) {
        this.#inFlight.delete(url);
      }
    }
  }

  /**
   * @param url - the URL to check
   * @returns true if the URL is cached and nott expired
   */
  public has(url: string): boolean {
    const cached = this.#cache.get(url);

    if (!cached) {
      return false;
    }

    const now = Date.now();

    if (cached.expiresAt <= now) {
      // expired, remove from cache
      this.#cache.delete(url);
      return false;
    }

    return true;
  }

  async #fetchAndCache(
    url: string,
    generation: number,
    urlGeneration: number,
  ): Promise<unknown> {
    // fetch fresh document, bounded by the configured timeout
    let res: Response;
    try {
      res = await fetch(url, {
        signal: AbortSignal.timeout(this.#timeoutMs),
      });
    } catch (error) {
      if (
        error instanceof Error &&
        (error.name === "AbortError" || error.name === "TimeoutError")
      ) {
        throw new Error(
          `Failed to fetch discovery document from ${url}: timed out after ${this.#timeoutMs}ms`,
        );
      }
      throw error;
    }

    if (!res.ok) {
      await cancelResponseBody(res);
      throw new Error(
        `Failed to fetch discovery document from ${url}: ${res.status} ${res.statusText}`,
      );
    }

    const data = await res.json();
    // calculate expiration time AFTER fetch completes
    const expiresAt = Date.now() + this.#ttl;

    // A clear that occurred while the fetch was pending invalidates its result.
    if (
      this.#generation === generation &&
      (this.#urlGenerations.get(url) ?? 0) === urlGeneration
    ) {
      this.#cache.set(url, {
        data,
        expiresAt,
      });
    }

    return data;
  }
}
