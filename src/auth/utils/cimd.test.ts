/**
 * Client ID Metadata Document (CIMD) resolver tests
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import { resolveCimdClient } from "./cimd.js";

const CLIENT_ID = "https://client.example.com/oauth/client-metadata.json";
const REDIRECT_URI = "http://127.0.0.1:33418/";

const alwaysAllow = () => true;
const alwaysDeny = () => false;

function mockFetchOnce(body: unknown, init: ResponseInit = {}) {
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(typeof body === "string" ? body : JSON.stringify(body), {
          headers: { "Content-Type": "application/json" },
          status: 200,
          ...init,
        }),
    ),
  );
}

function validDocument(overrides: Record<string, unknown> = {}) {
  return {
    client_id: CLIENT_ID,
    client_name: "Example Client",
    redirect_uris: [REDIRECT_URI],
    ...overrides,
  };
}

describe("resolveCimdClient", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("resolves a valid document into a ProxyDCRClient", async () => {
    mockFetchOnce(validDocument());

    const client = await resolveCimdClient(
      CLIENT_ID,
      REDIRECT_URI,
      alwaysAllow,
    );

    expect(client).not.toBeNull();
    expect(client?.clientId).toBe(CLIENT_ID);
    expect(client?.callbackUrl).toBe(REDIRECT_URI);
    expect(client?.redirectUris).toEqual([REDIRECT_URI]);
    expect(client?.clientSecret).toBeUndefined();
    expect(client?.metadata?.client_name).toBe("Example Client");
  });

  it("only reads recognised metadata fields, ignoring unknown ones", async () => {
    mockFetchOnce(
      validDocument({
        application_type: "native",
        token_endpoint_auth_method: "none",
      }),
    );

    const client = await resolveCimdClient(
      CLIENT_ID,
      REDIRECT_URI,
      alwaysAllow,
    );

    expect(client?.metadata).not.toHaveProperty("application_type");
    expect(client?.metadata).not.toHaveProperty("token_endpoint_auth_method");
  });

  it("rejects a client_id that is not a URL at all", async () => {
    const client = await resolveCimdClient(
      "not-a-url",
      REDIRECT_URI,
      alwaysAllow,
    );
    expect(client).toBeNull();
  });

  it("rejects a non-HTTPS client_id", async () => {
    const client = await resolveCimdClient(
      "http://client.example.com/client-metadata.json",
      REDIRECT_URI,
      alwaysAllow,
    );
    expect(client).toBeNull();
  });

  it("rejects a client_id with a query string", async () => {
    const client = await resolveCimdClient(
      `${CLIENT_ID}?x=1`,
      REDIRECT_URI,
      alwaysAllow,
    );
    expect(client).toBeNull();
  });

  it.each([
    "https://localhost/client.json",
    "https://127.0.0.1/client.json",
    "https://169.254.169.254/client.json",
    "https://10.0.0.5/client.json",
    "https://192.168.1.5/client.json",
    "https://172.16.0.5/client.json",
  ])(
    "rejects a loopback or private-range host without fetching it (%s)",
    async (loopbackClientId) => {
      const fetchSpy = vi.fn();
      vi.stubGlobal("fetch", fetchSpy);

      const client = await resolveCimdClient(
        loopbackClientId,
        REDIRECT_URI,
        alwaysAllow,
      );

      expect(client).toBeNull();
      expect(fetchSpy).not.toHaveBeenCalled();
    },
  );

  it("rejects when the fetch fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("network error");
      }),
    );

    const client = await resolveCimdClient(
      CLIENT_ID,
      REDIRECT_URI,
      alwaysAllow,
    );
    expect(client).toBeNull();
  });

  it("rejects a non-2xx response", async () => {
    mockFetchOnce(validDocument(), { status: 404 });

    const client = await resolveCimdClient(
      CLIENT_ID,
      REDIRECT_URI,
      alwaysAllow,
    );
    expect(client).toBeNull();
  });

  it("rejects a response body that is not valid JSON", async () => {
    mockFetchOnce("not json");

    const client = await resolveCimdClient(
      CLIENT_ID,
      REDIRECT_URI,
      alwaysAllow,
    );
    expect(client).toBeNull();
  });

  it("rejects a response larger than the size cap", async () => {
    mockFetchOnce(validDocument({ client_name: "x".repeat(100_000) }));

    const client = await resolveCimdClient(
      CLIENT_ID,
      REDIRECT_URI,
      alwaysAllow,
    );
    expect(client).toBeNull();
  });

  it("rejects a document whose client_id does not match the fetch URL", async () => {
    mockFetchOnce(
      validDocument({ client_id: "https://attacker.example.com/client.json" }),
    );

    const client = await resolveCimdClient(
      CLIENT_ID,
      REDIRECT_URI,
      alwaysAllow,
    );
    expect(client).toBeNull();
  });

  it("rejects a document with no redirect_uris", async () => {
    mockFetchOnce(validDocument({ redirect_uris: [] }));

    const client = await resolveCimdClient(
      CLIENT_ID,
      REDIRECT_URI,
      alwaysAllow,
    );
    expect(client).toBeNull();
  });

  it("rejects a document whose redirect_uris does not include the requested redirect_uri", async () => {
    mockFetchOnce(validDocument({ redirect_uris: ["http://127.0.0.1:9999/"] }));

    const client = await resolveCimdClient(
      CLIENT_ID,
      REDIRECT_URI,
      alwaysAllow,
    );
    expect(client).toBeNull();
  });

  it("accepts a document when requestedRedirectUri is omitted (token-exchange call sites)", async () => {
    mockFetchOnce(validDocument());

    const client = await resolveCimdClient(CLIENT_ID, undefined, alwaysAllow);
    expect(client).not.toBeNull();
  });

  it("rejects every redirect_uri that fails the caller's allow-list check", async () => {
    mockFetchOnce(validDocument());

    const client = await resolveCimdClient(CLIENT_ID, REDIRECT_URI, alwaysDeny);
    expect(client).toBeNull();
  });

  it("never throws — resolves to null even for a malformed URL constructor edge case", async () => {
    await expect(
      resolveCimdClient("https://", REDIRECT_URI, alwaysAllow),
    ).resolves.toBeNull();
  });
});
