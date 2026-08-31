import type { HttpRoute } from "./types.js";

const MAX_NAME_LENGTH = 56;
// Reserves room for a "_<n>" collision suffix so the final name never
// exceeds MAX_NAME_LENGTH, however many collisions it takes.
const MAX_BASE_LENGTH = MAX_NAME_LENGTH - 5;

/**
 * Generates a unique tool name per route.
 *
 * Ports the Python implementation's naming rule
 * (`server/providers/openapi/provider.py:_generate_default_name`): prefer
 * `mcpNames[operationId]`, then `operationId` (FastAPI-style `__` suffixes
 * stripped), falling back to `summary` or `{method}_{path}`; slugified and
 * capped at 56 characters, with `_2`, `_3`, ... appended on collision.
 *
 * Uniqueness is checked against the final (post-suffix) name, not just the
 * base — otherwise a spec whose own operationIds already look auto-suffixed
 * (e.g. both "foo" and "foo_2" present) could produce two identically-named
 * tools, one of which `FastMCP.addTool` would silently drop.
 */
export function generateToolNames(
  routes: HttpRoute[],
  mcpNames: Record<string, string> | undefined,
): Map<HttpRoute, string> {
  const names = new Map<HttpRoute, string>();
  const used = new Set<string>();

  for (const route of routes) {
    const base = slugify(baseNameFor(route, mcpNames));
    let candidate = base;
    let suffix = 1;

    while (used.has(candidate)) {
      suffix += 1;
      candidate = `${base}_${suffix}`;
    }

    used.add(candidate);
    names.set(route, candidate);
  }

  return names;
}

function baseNameFor(
  route: HttpRoute,
  mcpNames: Record<string, string> | undefined,
): string {
  if (route.operationId) {
    return mcpNames?.[route.operationId] ?? route.operationId.split("__")[0];
  }

  return route.summary || `${route.method}_${route.path}`;
}

function slugify(value: string): string {
  const slug = value
    .replace(/[^a-zA-Z0-9_]+/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_|_$/g, "")
    .slice(0, MAX_BASE_LENGTH);

  return slug || "operation";
}
