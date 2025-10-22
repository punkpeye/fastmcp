import { setTimeout as delay } from "timers/promises";
import { expect, test, vi } from "vitest";

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
    json: async () => mockResponse,
    ok: true,
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
      json: async () => mockResponse1,
      ok: true,
    } as Response)
    .mockResolvedValueOnce({
      json: async () => mockResponse2,
      ok: true,
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
      json: async () => mockResponse,
      ok: true,
    } as Response)
    .mockResolvedValueOnce({
      json: async () => mockResponse,
      ok: true,
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
    json: async () => mockResponse,
    ok: true,
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
    json: async () => mockResponse,
    ok: true,
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
    json: async () => mockResponse,
    ok: true,
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
    json: async () => mockResponse,
    ok: true,
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
      json: async () => mockResponse1,
      ok: true,
    } as Response)
    .mockResolvedValueOnce({
      json: async () => mockResponse2,
      ok: true,
    } as Response);
  const result1 = await cache.get(url1);
  const result2 = await cache.get(url2);

  expect(result1).toEqual(mockResponse1);
  expect(result2).toEqual(mockResponse2);
  expect(cache.size).toBe(2);
  expect(fetchSpy).toHaveBeenCalledTimes(2);

  fetchSpy.mockRestore();
});

test("coalesces concurrent requests to prevent duplicate fetches", async () => {
  const cache = new DiscoveryDocumentCache();
  const testUrl = "https://auth.example.com/.well-known/openid-configuration";
  const mockResponse = { issuer: "https://auth.example.com" };

  let fetchCallCount = 0;

  const fetchSpy = vi.spyOn(global, "fetch").mockImplementation(async () => {
    fetchCallCount++;

    await delay(100); // simulate network delay
    return {
      json: async () => mockResponse,
      ok: true,
    } as Response;
  });

  // make 5 concurrent requests
  const promises = Array.from({ length: 5 }, () => cache.get(testUrl));
  const results = await Promise.all(promises);

  // all should return the same data
  results.forEach((result) => {
    expect(result).toEqual(mockResponse);
  });

  // but fetch should only be called once
  expect(fetchCallCount).toBe(1);
  expect(cache.size).toBe(1);

  fetchSpy.mockRestore();
});

test("calculates TTL after fetch completes, not before", async () => {
  const cache = new DiscoveryDocumentCache({ ttl: 1000 }); // 1 second TTL
  const testUrl = "https://auth.example.com/.well-known/openid-configuration";
  const mockResponse = { issuer: "https://auth.example.com" };
  const fetchSpy = vi.spyOn(global, "fetch").mockImplementation(async () => {
    await delay(500); // simulate slow network - 500ms

    return {
      json: async () => mockResponse,
      ok: true,
    } as Response;
  });

  const startTime = Date.now();

  await cache.get(testUrl);

  const fetchDuration = Date.now() - startTime;

  // verify fetch took around 500ms
  expect(fetchDuration).toBeGreaterThanOrEqual(450);

  // wait 600ms (less than TTL of 1000ms)
  await delay(600);

  // should still be cached (TTL is 1000ms from when fetch completed, not started)
  expect(cache.has(testUrl)).toBe(true);

  // should use cache, not fetch again
  await cache.get(testUrl);

  expect(fetchSpy).toHaveBeenCalledTimes(1);

  fetchSpy.mockRestore();
});

test("handles concurrent requests with slow fetch correctly", async () => {
  const cache = new DiscoveryDocumentCache();
  const testUrl = "https://auth.example.com/.well-known/openid-configuration";
  const mockResponse = { issuer: "https://auth.example.com" };

  let fetchCallCount = 0;

  const fetchSpy = vi.spyOn(global, "fetch").mockImplementation(async () => {
    fetchCallCount++;

    await delay(200); // slow fetch

    return {
      json: async () => mockResponse,
      ok: true,
    } as Response;
  });

  // start first request
  const promise1 = cache.get(testUrl);

  // start second request after 50ms
  // (while first is still in flight)

  await delay(50);

  const promise2 = cache.get(testUrl);
  // both should resolve with the same data
  const [result1, result2] = await Promise.all([promise1, promise2]);

  expect(result1).toEqual(mockResponse);
  expect(result2).toEqual(mockResponse);
  expect(fetchCallCount).toBe(1); // should only fetch once

  fetchSpy.mockRestore();
});
