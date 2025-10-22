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

  #inFlight: Map<string, Promise<unknown>> = new Map();

  #ttl: number;

  /**
   * @param options - configuration options
   * @param options.ttl - time-to-live in miliseconds
   */
  public constructor(options: { ttl?: number } = {}) {
    this.#ttl = options.ttl ?? 3600000; // default 1 hour
  }

  /**
   * @param url - optional URL to clear. if omitted, clears all cached documents.
   */
  public clear(url?: string): void {
    if (url) {
      this.#cache.delete(url);
    } else {
      this.#cache.clear();
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
    const fetchPromise = this.#fetchAndCache(url);

    this.#inFlight.set(url, fetchPromise);

    try {
      const data = await fetchPromise;
      return data;
    } finally {
      // clean up in-flight promise after completion
      // (success or failure)
      this.#inFlight.delete(url);
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

  async #fetchAndCache(url: string): Promise<unknown> {
    // fetch fresh document
    const res = await fetch(url);

    if (!res.ok) {
      throw new Error(
        `Failed to fetch discovery document from ${url}: ${res.status} ${res.statusText}`,
      );
    }

    const data = await res.json();
    // calculate expiration time AFTER fetch completes
    const expiresAt = Date.now() + this.#ttl;

    // store in cache with expiration
    this.#cache.set(url, {
      data,
      expiresAt,
    });

    return data;
  }
}
