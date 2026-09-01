import { defineConfig } from "vitest/config";

// fromOpenAPI.benchmark.test.ts runs separately via `pnpm bench:openapi` (its
// own CI job) — large real-world specs make it too slow for the regular
// `pnpm test` loop, so it's excluded here unless OPENAPI_BENCHMARK is set.
const exclude = ["**/node_modules/**"];

if (!process.env.OPENAPI_BENCHMARK) {
  exclude.push("**/fromOpenAPI.benchmark.test.ts");
}

export default defineConfig({
  test: {
    exclude,
    poolOptions: {
      forks: { execArgv: ["--experimental-eventsource"] },
    },
  },
});
