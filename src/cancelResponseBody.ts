/**
 * Release for unread `fetch` response bodies, shared by every call site that
 * throws on a non-2xx response.
 */

/**
 * Discard a response body the caller is never going to read.
 *
 * Node does not free the socket behind a `fetch` response until its body is
 * consumed or cancelled. An error path that inspects `response.ok` and throws
 * therefore strands one connection per failed request, released only whenever
 * the garbage collector happens to reach the response — so a server answering
 * a stream of 5xx responses accumulates open sockets.
 *
 * Cancellation failures are swallowed on purpose: this runs while an HTTP
 * error is already on its way to the caller, and that error's status is a far
 * more useful diagnostic than whatever went wrong tearing down the stream.
 */
export const cancelResponseBody = async (response: Response): Promise<void> => {
  if (!response.body) {
    return;
  }

  try {
    await response.body.cancel();
  } catch {
    // Deliberately ignored; see above.
  }
};
