import { expect, test, vi } from "vitest";
import { setTimeout as delay } from "timers/promises";
import { DiscoveryDocumentCache } from "./DiscoveryDocumentCache.js";

test("caches discovery documents", async () => {
  const cache = new DiscoveryDocumentCache();
  const testUrl = "https://auth.example.com/.well-known/openid-configuration";
  const mockResponse = {
    issuer: "https://auth.example.com",
    jwks_uri: "https://auth.example.com/.well-known/jwks.json",
  };
  // mock fetch
  const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValueOnce({
    ok: true,
    json: async () => mockResponse,
  } as Response);
  // first call should fetch
  const result1 = await cache.get(testUrl);

  expect(result1).toEqual(mockResponse);
  expect(fetchSpy).toHaveBeenCalledTimes(1);

  // second call should use cache
  const result2 = await cache.get(testUrl);

  expect(result2).toEqual(mockResponse);
  expect(fetchSpy).toHaveBeenCalledTimes(1); // still 1, not 2

  fetchSpy.mockRestore();
});

test("respects TTL and refetches after expiration", async () => {
  const cache = new DiscoveryDocumentCache({ ttl: 100 }); // 100ms TTL
  const testUrl = "https://auth.example.com/.well-known/openid-configuration";
  const mockResponse1 = {
    issuer: "https://auth.example.com",
    version: 1,
  };
  const mockResponse2 = {
    issuer: "https://auth.example.com",
    version: 2,
  };
  const fetchSpy = vi
    .spyOn(global, "fetch")
    .mockResolvedValueOnce({
      ok: true,
      json: async () => mockResponse1,
    } as Response)
    .mockResolvedValueOnce({
      ok: true,
      json: async () => mockResponse2,
    } as Response);
  // first call
  const result1 = await cache.get(testUrl);

  expect(result1).toEqual(mockResponse1);
  expect(fetchSpy).toHaveBeenCalledTimes(1);

  // wait for TTL to expire
  await delay(150);

  // second call should refetch
  const result2 = await cache.get(testUrl);

  expect(result2).toEqual(mockResponse2);
  expect(fetchSpy).toHaveBeenCalledTimes(2);

  fetchSpy.mockRestore();
});

test("throws error on failed fetch", async () => {
  const cache = new DiscoveryDocumentCache();
  const testUrl = "https://auth.example.com/.well-known/openid-configuration";
  const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValueOnce({
    ok: false,
    status: 404,
    statusText: "Not Found",
  } as Response);

  await expect(cache.get(testUrl)).rejects.toThrow(
    "Failed to fetch discovery document from https://auth.example.com/.well-known/openid-configuration: 404 Not Found",
  );

  fetchSpy.mockRestore();
});

test("clears specific URL from cache", async () => {
  const cache = new DiscoveryDocumentCache();
  const testUrl = "https://auth.example.com/.well-known/openid-configuration";
  const mockResponse = { issuer: "https://auth.example.com" };
  const fetchSpy = vi
    .spyOn(global, "fetch")
    .mockResolvedValueOnce({
      ok: true,
      json: async () => mockResponse,
    } as Response)
    .mockResolvedValueOnce({
      ok: true,
      json: async () => mockResponse,
    } as Response);

  // fetch and cache
  await cache.get(testUrl);

  expect(cache.has(testUrl)).toBe(true);
  expect(cache.size).toBe(1);

  // clear the specific URL
  cache.clear(testUrl);

  expect(cache.has(testUrl)).toBe(false);
  expect(cache.size).toBe(0);

  // next fetch should hit the network again
  await cache.get(testUrl);

  expect(fetchSpy).toHaveBeenCalledTimes(2);

  fetchSpy.mockRestore();
});

test("clears all cached documents", async () => {
  const cache = new DiscoveryDocumentCache();
  const url1 = "https://auth1.example.com/.well-known/openid-configuration";
  const url2 = "https://auth2.example.com/.well-known/openid-configuration";
  const mockResponse = { issuer: "https://auth.example.com" };
  const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValue({
    ok: true,
    json: async () => mockResponse,
  } as Response);

  // fetch and cache both URLs
  await cache.get(url1);
  await cache.get(url2);

  expect(cache.size).toBe(2);

  // clear all
  cache.clear();

  expect(cache.size).toBe(0);
  expect(cache.has(url1)).toBe(false);
  expect(cache.has(url2)).toBe(false);

  fetchSpy.mockRestore();
});

test("has() returns false for expired entries", async () => {
  const cache = new DiscoveryDocumentCache({ ttl: 100 }); // 100ms TTL
  const testUrl = "https://auth.example.com/.well-known/openid-configuration";
  const mockResponse = { issuer: "https://auth.example.com" };
  const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValueOnce({
    ok: true,
    json: async () => mockResponse,
  } as Response);

  // fetch and cache
  await cache.get(testUrl);

  expect(cache.has(testUrl)).toBe(true);

  // wait for expiration
  await delay(150);

  // has() should return false and clean up expired entry
  expect(cache.has(testUrl)).toBe(false);
  expect(cache.size).toBe(0);

  fetchSpy.mockRestore();
});

test("uses default TTL of 1 hour", async () => {
  const cache = new DiscoveryDocumentCache();
  const testUrl = "https://auth.example.com/.well-known/openid-configuration";
  const mockResponse = { issuer: "https://auth.example.com" };
  const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValueOnce({
    ok: true,
    json: async () => mockResponse,
  } as Response);

  await cache.get(testUrl);
  await delay(100); // the cache should still be valid for a long time

  expect(cache.has(testUrl)).toBe(true);

  fetchSpy.mockRestore();
});

test("supports custom TTL values", async () => {
  const cache = new DiscoveryDocumentCache({ ttl: 50 }); // 50ms
  const testUrl = "https://auth.example.com/.well-known/openid-configuration";
  const mockResponse = { issuer: "https://auth.example.com" };
  const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValueOnce({
    ok: true,
    json: async () => mockResponse,
  } as Response);

  await cache.get(testUrl);
  await delay(25); // before TTL expires

  expect(cache.has(testUrl)).toBe(true);

  await delay(50); // after TTL expires

  expect(cache.has(testUrl)).toBe(false);

  fetchSpy.mockRestore();
});

test("caches multiple different URLs independently", async () => {
  const cache = new DiscoveryDocumentCache();
  const url1 = "https://auth1.example.com/.well-known/openid-configuration";
  const url2 = "https://auth2.example.com/.well-known/openid-configuration";
  const mockResponse1 = { issuer: "https://auth1.example.com" };
  const mockResponse2 = { issuer: "https://auth2.example.com" };
  const fetchSpy = vi
    .spyOn(global, "fetch")
    .mockResolvedValueOnce({
      ok: true,
      json: async () => mockResponse1,
    } as Response)
    .mockResolvedValueOnce({
      ok: true,
      json: async () => mockResponse2,
    } as Response);
  const result1 = await cache.get(url1);
  const result2 = await cache.get(url2);

  expect(result1).toEqual(mockResponse1);
  expect(result2).toEqual(mockResponse2);
  expect(cache.size).toBe(2);
  expect(fetchSpy).toHaveBeenCalledTimes(2);

  fetchSpy.mockRestore();
});
