import type {
  FromOpenAPIOptions,
  HttpMethod,
  HttpRoute,
  OperationSummary,
} from "./types.js";

/**
 * If neither `include`/`exclude` nor `maxTools` was given, and a spec still
 * produces more operations than this, `selectRoutes` throws rather than
 * silently generating a wall of tools most clients can't usefully work with.
 */
export const DEFAULT_MAX_OPERATIONS = 40;

const METHOD_PRIORITY: Record<HttpMethod, number> = {
  delete: 4,
  get: 0,
  patch: 3,
  post: 1,
  put: 2,
};

/**
 * Filters and orders routes into the set that becomes tools.
 *
 * Deprecated operations are excluded by default. Ordering is deterministic
 * (method priority GET→POST→PUT→PATCH→DELETE, then path) so that, combined
 * with `maxTools`, truncation is legible rather than arbitrary.
 */
export function selectRoutes(
  routes: HttpRoute[],
  options: Pick<FromOpenAPIOptions, "exclude" | "include" | "maxTools">,
): HttpRoute[] {
  let selected = routes.filter((route) => !route.deprecated);

  if (options.include) {
    const include = options.include;
    selected = selected.filter((route) => include(toSummary(route)));
  }

  if (options.exclude) {
    const exclude = options.exclude;
    selected = selected.filter((route) => !exclude(toSummary(route)));
  }

  selected = [...selected].sort((a, b) => {
    const byMethod = METHOD_PRIORITY[a.method] - METHOD_PRIORITY[b.method];
    return byMethod !== 0 ? byMethod : a.path.localeCompare(b.path);
  });

  const noSelectionGiven = !options.include && !options.exclude;

  if (
    noSelectionGiven &&
    options.maxTools === undefined &&
    selected.length > DEFAULT_MAX_OPERATIONS
  ) {
    throw new Error(
      `fromOpenAPI found ${selected.length} operations, which exceeds the default limit of ${DEFAULT_MAX_OPERATIONS}. ` +
        "This is a deliberate stop, not a bug: turning every operation in a large spec into a tool produces a tool list most MCP clients can't use well. " +
        "Pass `include`/`exclude` to choose the operations you actually want, or `maxTools` to raise this limit explicitly.",
    );
  }

  if (options.maxTools !== undefined && selected.length > options.maxTools) {
    throw new Error(
      `fromOpenAPI found ${selected.length} operations, which exceeds maxTools (${options.maxTools}). ` +
        "Narrow the spec with `include`/`exclude`, or raise `maxTools`.",
    );
  }

  return selected;
}

function toSummary(route: HttpRoute): OperationSummary {
  return {
    deprecated: route.deprecated,
    method: route.method,
    operationId: route.operationId,
    path: route.path,
    tags: route.tags,
  };
}
