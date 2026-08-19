import { expect, test, vi } from "vitest";

import { cancelResponseBody } from "./cancelResponseBody.js";

/**
 * Builds the slice of Response the helper touches. Anything it is not
 * supposed to read is absent, so an unexpected access fails loudly.
 */
const responseWithBody = (cancel: () => Promise<undefined>) =>
  ({ body: { cancel } }) as unknown as Response;

test("cancels a body the caller will not read", async () => {
  const cancel = vi.fn(async () => undefined);

  await cancelResponseBody(responseWithBody(cancel));

  expect(cancel).toHaveBeenCalledOnce();
});

test("is a no-op for a response without a body", async () => {
  // 204s and HEAD responses have no body to release.
  await expect(
    cancelResponseBody({ body: null } as Response),
  ).resolves.toBeUndefined();
});

test("swallows a cancellation failure", async () => {
  // The caller is already throwing an HTTP error; that status is the more
  // useful diagnostic, so a failed teardown must not displace it.
  const cancel = vi.fn(async () => {
    throw new Error("stream already errored");
  });

  await expect(
    cancelResponseBody(responseWithBody(cancel as () => Promise<undefined>)),
  ).resolves.toBeUndefined();

  expect(cancel).toHaveBeenCalledOnce();
});
