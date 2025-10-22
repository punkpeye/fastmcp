export class DiscoveryDocumentCache {
  #cache: Map<
    string,
    {
      data: unknown;
      expiresAt: number;
    }
  > = new Map();

  #ttl: number;

  /**
   * @param options - configuration options
   * @param options.ttl - time-to-live in miliseconds
   */
  public constructor(options: { ttl?: number } = {}) {
    this.#ttl = options.ttl ?? 3600000; // default 1 hour
  }

  /**
   * fetches a discovery document from the given URL.
   * uses cached value if available and not expired.
   *
   * @param url - the discovery document URL (e.g., /.well-known/openid-configuration)
   * @returns the discovery document as a JSON object
   * @throws Error if the fetch fails or returns non-OK status
   */
  public async get(url: string): Promise<unknown> {
    const cached = this.#cache.get(url);
    const now = Date.now();

    // return cached value if still valid
    if (cached && cached.expiresAt > now) {
      return cached.data;
    }

    // fetch fresh document
    const res = await fetch(url);

    if (!res.ok) {
      throw new Error(
        `Failed to fetch discovery document from ${url}: ${res.status} ${res.statusText}`,
      );
    }

    const data = await res.json();

    // store in cache with expiration
    this.#cache.set(url, {
      data,
      expiresAt: now + this.#ttl,
    });

    return data;
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

  public get size(): number {
    return this.#cache.size;
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
}
