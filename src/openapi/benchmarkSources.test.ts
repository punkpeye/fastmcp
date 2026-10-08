import { describe, expect, it } from "vitest";

import {
  githubRawUrl,
  parseGitHubRawUrl,
  readManifest,
  // @ts-expect-error -- plain .mjs helper, shared with the refresh script
} from "./__fixtures__/ensureBenchmarkSpecs.mjs";

describe("benchmark spec sources", () => {
  // A branch URL serves whatever was pushed last, so its sha256 pin broke
  // whenever upstream touched the file. A commit URL cannot change under it.
  it("fetches every GitHub-hosted spec from a pinned commit", async () => {
    const manifest: Record<string, { track?: string; url: string }> =
      await readManifest();
    const github = Object.entries(manifest).filter(([, { url }]) =>
      url.startsWith("https://raw.githubusercontent.com/"),
    );

    expect(github.length).toBeGreaterThan(0);

    for (const [file, { track, url }] of github) {
      const source = parseGitHubRawUrl(url);

      expect(source, file).toBeDefined();
      expect(source?.ref, file).toMatch(/^[0-9a-f]{40}$/);
      expect(track, file).toEqual(expect.any(String));
    }
  });

  it("rebuilds a raw URL for another commit", () => {
    const source = parseGitHubRawUrl(
      "https://raw.githubusercontent.com/twilio/twilio-oai/main/spec/json/twilio_api_v2010.json",
    );

    expect(source).toEqual({
      owner: "twilio",
      path: "spec/json/twilio_api_v2010.json",
      ref: "main",
      repo: "twilio-oai",
    });
    expect(githubRawUrl(source!, "a".repeat(40))).toBe(
      `https://raw.githubusercontent.com/twilio/twilio-oai/${"a".repeat(40)}/spec/json/twilio_api_v2010.json`,
    );
    expect(parseGitHubRawUrl("https://app.posthog.com/api/schema/")).toBe(
      undefined,
    );
  });
});
