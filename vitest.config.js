import { defineConfig } from "vitest/config";

// Both of these reach the network — the benchmark fetches large real-world
// specs, and the live test calls the public Petstore API. They run in their
// own CI job via `pnpm test:openapi`, so a third-party outage can't fail
// `pnpm test` on an unrelated PR.
const exclude = ["**/node_modules/**"];

if (!process.env.OPENAPI_NETWORK) {
  exclude.push(
    "**/fromOpenAPI.benchmark.test.ts",
    "**/fromOpenAPI.live.test.ts",
  );
}

export default defineConfig({
  test: {
    exclude,
    poolOptions: {
      forks: { execArgv: ["--experimental-eventsource"] },
    },
  },
});
